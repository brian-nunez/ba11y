package v1

import (
	"github.com/labstack/echo/v4"
)

func HealthHandler(c echo.Context) error {
	return c.JSON(200, map[string]string{
		"status":  "ok",
		"message": "Service is running",
		"TODO":    "UPDATE TO USE A REAL HEALTH CHECK",
	})
}
