package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidEmail       = errors.New("invalid email")
	ErrPasswordTooShort   = errors.New("password must be at least 8 characters")
	ErrEmailAlreadyExists = errors.New("email is already registered")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrSessionExpired     = errors.New("session has expired")
)

type User struct {
	ID        string
	Email     string
	Roles     []string
	CreatedAt time.Time
}

func (u User) IsAdmin() bool {
	return slices.Contains(u.Roles, "admin")
}

type storedUser struct {
	User         User
	PasswordHash []byte
}

type sessionRecord struct {
	UserID    string
	ExpiresAt time.Time
}

type Service struct {
	mu            sync.RWMutex
	usersByID     map[string]*storedUser
	userIDByEmail map[string]string
	sessions      map[string]sessionRecord
	sessionTTL    time.Duration
	now           func() time.Time
}

func NewService() *Service {
	return &Service{
		usersByID:     make(map[string]*storedUser),
		userIDByEmail: make(map[string]string),
		sessions:      make(map[string]sessionRecord),
		sessionTTL:    30 * 24 * time.Hour,
		now:           time.Now,
	}
}

func (s *Service) Register(_ context.Context, email string, password string) (User, error) {
	normalizedEmail, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	if len(password) < 8 {
		return User{}, ErrPasswordTooShort
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.userIDByEmail[normalizedEmail]; exists {
		return User{}, ErrEmailAlreadyExists
	}

	roles := []string{"user"}
	if len(s.usersByID) == 0 {
		roles = []string{"admin", "user"}
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}

	id, err := generateToken("usr", 12)
	if err != nil {
		return User{}, fmt.Errorf("generate user id: %w", err)
	}

	stored := &storedUser{
		User: User{
			ID:        id,
			Email:     normalizedEmail,
			Roles:     roles,
			CreatedAt: s.now().UTC(),
		},
		PasswordHash: passwordHash,
	}

	s.usersByID[stored.User.ID] = stored
	s.userIDByEmail[normalizedEmail] = stored.User.ID

	return cloneUser(stored.User), nil
}

func (s *Service) Login(_ context.Context, email string, password string) (User, string, error) {
	normalizedEmail, err := normalizeEmail(email)
	if err != nil {
		return User{}, "", ErrInvalidCredentials
	}

	s.mu.RLock()
	userID, exists := s.userIDByEmail[normalizedEmail]
	if !exists {
		s.mu.RUnlock()
		return User{}, "", ErrInvalidCredentials
	}
	stored := s.usersByID[userID]
	s.mu.RUnlock()

	if err := bcrypt.CompareHashAndPassword(stored.PasswordHash, []byte(password)); err != nil {
		return User{}, "", ErrInvalidCredentials
	}

	sessionToken, err := generateToken("sess", 24)
	if err != nil {
		return User{}, "", fmt.Errorf("generate session token: %w", err)
	}

	s.mu.Lock()
	s.sessions[sessionToken] = sessionRecord{
		UserID:    stored.User.ID,
		ExpiresAt: s.now().UTC().Add(s.sessionTTL),
	}
	s.mu.Unlock()

	return cloneUser(stored.User), sessionToken, nil
}

func (s *Service) AuthenticateSession(_ context.Context, sessionToken string) (User, bool, error) {
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return User{}, false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session, found := s.sessions[sessionToken]
	if !found {
		return User{}, false, nil
	}

	now := s.now().UTC()
	if !session.ExpiresAt.After(now) {
		delete(s.sessions, sessionToken)
		return User{}, false, ErrSessionExpired
	}

	stored, exists := s.usersByID[session.UserID]
	if !exists {
		delete(s.sessions, sessionToken)
		return User{}, false, nil
	}

	return cloneUser(stored.User), true, nil
}

func (s *Service) Logout(_ context.Context, sessionToken string) error {
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return nil
	}

	s.mu.Lock()
	delete(s.sessions, sessionToken)
	s.mu.Unlock()

	return nil
}

func normalizeEmail(value string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(value))
	if email == "" {
		return "", ErrInvalidEmail
	}

	if _, err := mail.ParseAddress(email); err != nil {
		return "", ErrInvalidEmail
	}

	return email, nil
}

func generateToken(prefix string, byteLength int) (string, error) {
	if byteLength <= 0 {
		byteLength = 16
	}
	buffer := make([]byte, byteLength)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	if strings.TrimSpace(prefix) == "" {
		return base64.RawURLEncoding.EncodeToString(buffer), nil
	}

	return prefix + "_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func cloneUser(user User) User {
	roles := make([]string, len(user.Roles))
	copy(roles, user.Roles)

	return User{
		ID:        user.ID,
		Email:     user.Email,
		Roles:     roles,
		CreatedAt: user.CreatedAt,
	}
}
