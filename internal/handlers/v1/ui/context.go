package uihandlers

import (
	"github.com/brian-nunez/ba11y/internal/auth"
	"github.com/labstack/echo/v4"
)

const currentUserKey = "current_user"

func setCurrentUser(c echo.Context, user auth.User) {
	c.Set(currentUserKey, user)
}

func getCurrentUser(c echo.Context) (auth.User, bool) {
	value := c.Get(currentUserKey)
	if value == nil {
		return auth.User{}, false
	}

	user, ok := value.(auth.User)
	if !ok {
		return auth.User{}, false
	}

	return user, true
}
