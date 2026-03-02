package uihandlers

import (
	"errors"
	"net/http"

	"github.com/brian-nunez/ba11y/internal/auth"
	"github.com/labstack/echo/v4"
)

const sessionCookieName = "bbaas_session"

func SessionMiddleware(authService *auth.Service) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			sessionCookie, err := c.Cookie(sessionCookieName)
			if err == nil && sessionCookie != nil && sessionCookie.Value != "" {
				user, authenticated, authErr := authService.AuthenticateSession(c.Request().Context(), sessionCookie.Value)
				if authErr != nil && !errors.Is(authErr, auth.ErrSessionExpired) {
					return authErr
				}
				if authenticated {
					setCurrentUser(c, user)
				} else {
					clearSessionCookie(c)
				}
			}

			return next(c)
		}
	}
}

func RequireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if _, ok := getCurrentUser(c); !ok {
			return c.Redirect(http.StatusSeeOther, "/login")
		}

		return next(c)
	}
}

func RequireAuthAPI(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if _, ok := getCurrentUser(c); !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
		}

		return next(c)
	}
}

func RequireGuest(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if _, ok := getCurrentUser(c); ok {
			return c.Redirect(http.StatusSeeOther, "/scans/new")
		}

		return next(c)
	}
}

func setSessionCookie(c echo.Context, token string) {
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Scheme() == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((30 * 24 * 60 * 60)),
	}
	c.SetCookie(cookie)
}

func clearSessionCookie(c echo.Context) {
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Scheme() == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	c.SetCookie(cookie)
}
