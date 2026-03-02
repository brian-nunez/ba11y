package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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

type Service struct {
	mu         sync.Mutex
	db         *sql.DB
	sessionTTL time.Duration
	now        func() time.Time
}

func NewService(db *sql.DB) (*Service, error) {
	if db == nil {
		return nil, fmt.Errorf("auth database is nil")
	}

	service := &Service{
		db:         db,
		sessionTTL: 30 * 24 * time.Hour,
		now:        time.Now,
	}

	if err := service.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("ensure auth schema: %w", err)
	}

	if err := service.deleteExpiredSessions(context.Background()); err != nil {
		return nil, fmt.Errorf("cleanup expired sessions: %w", err)
	}

	return service, nil
}

func (s *Service) Register(ctx context.Context, email string, password string) (User, error) {
	normalizedEmail, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	if len(password) < 8 {
		return User{}, ErrPasswordTooShort
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}

	id, err := generateToken("usr", 12)
	if err != nil {
		return User{}, fmt.Errorf("generate user id: %w", err)
	}

	now := s.now().UTC()
	user := User{
		ID:        id,
		Email:     normalizedEmail,
		Roles:     []string{"user"},
		CreatedAt: now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin register transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var emailExists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE email = ? LIMIT 1`, normalizedEmail).Scan(&emailExists)
	if err == nil {
		return User{}, ErrEmailAlreadyExists
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("check existing email: %w", err)
	}

	var userCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&userCount); err != nil {
		return User{}, fmt.Errorf("count users: %w", err)
	}
	if userCount == 0 {
		user.Roles = []string{"admin", "user"}
	}

	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return User{}, fmt.Errorf("marshal roles: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO users (id, email, password_hash, roles, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, user.ID, user.Email, passwordHash, string(rolesJSON), formatTime(user.CreatedAt))
	if err != nil {
		return User{}, fmt.Errorf("insert user: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit register transaction: %w", err)
	}

	return cloneUser(user), nil
}

func (s *Service) Login(ctx context.Context, email string, password string) (User, string, error) {
	normalizedEmail, err := normalizeEmail(email)
	if err != nil {
		return User{}, "", ErrInvalidCredentials
	}

	var (
		rolesRaw    string
		createdAt   string
		stored      storedUser
		sessionTime = s.now().UTC()
	)

	err = s.db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, roles, created_at
		FROM users
		WHERE email = ?
		LIMIT 1
	`, normalizedEmail).Scan(
		&stored.User.ID,
		&stored.User.Email,
		&stored.PasswordHash,
		&rolesRaw,
		&createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrInvalidCredentials
	}
	if err != nil {
		return User{}, "", fmt.Errorf("load user for login: %w", err)
	}

	stored.User.Roles, err = parseRoles(rolesRaw)
	if err != nil {
		return User{}, "", fmt.Errorf("parse user roles: %w", err)
	}
	stored.User.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return User{}, "", fmt.Errorf("parse user creation time: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword(stored.PasswordHash, []byte(password)); err != nil {
		return User{}, "", ErrInvalidCredentials
	}

	sessionToken, err := generateToken("sess", 24)
	if err != nil {
		return User{}, "", fmt.Errorf("generate session token: %w", err)
	}

	expiresAt := sessionTime.Add(s.sessionTTL)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sessions (token, user_id, expires_at, created_at)
		VALUES (?, ?, ?, ?)
	`, sessionToken, stored.User.ID, formatTime(expiresAt), formatTime(sessionTime))
	if err != nil {
		return User{}, "", fmt.Errorf("insert session: %w", err)
	}

	return cloneUser(stored.User), sessionToken, nil
}

func (s *Service) AuthenticateSession(ctx context.Context, sessionToken string) (User, bool, error) {
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return User{}, false, nil
	}

	var (
		rolesRaw   string
		createdAt  string
		expiresAt  string
		authUser   User
		expiryTime time.Time
		err        error
	)

	err = s.db.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.roles, u.created_at, s.expires_at
		FROM sessions AS s
		INNER JOIN users AS u ON u.id = s.user_id
		WHERE s.token = ?
		LIMIT 1
	`, sessionToken).Scan(
		&authUser.ID,
		&authUser.Email,
		&rolesRaw,
		&createdAt,
		&expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("load session: %w", err)
	}

	authUser.Roles, err = parseRoles(rolesRaw)
	if err != nil {
		return User{}, false, fmt.Errorf("parse user roles: %w", err)
	}
	authUser.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return User{}, false, fmt.Errorf("parse user creation time: %w", err)
	}
	expiryTime, err = parseTime(expiresAt)
	if err != nil {
		_ = s.Logout(ctx, sessionToken)
		return User{}, false, nil
	}

	if !expiryTime.After(s.now().UTC()) {
		_ = s.Logout(ctx, sessionToken)
		return User{}, false, ErrSessionExpired
	}

	return cloneUser(authUser), true, nil
}

func (s *Service) Logout(ctx context.Context, sessionToken string) error {
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return nil
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, sessionToken); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

func (s *Service) ensureSchema(ctx context.Context) error {
	statements := []string{
		`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			password_hash BLOB NOT NULL,
			roles TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
		`,
		`
		CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);`,
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) deleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, formatTime(s.now().UTC()))
	if err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}
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

func parseRoles(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return []string{"user"}, nil
	}

	var roles []string
	if err := json.Unmarshal([]byte(value), &roles); err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return []string{"user"}, nil
	}

	return roles, nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
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
