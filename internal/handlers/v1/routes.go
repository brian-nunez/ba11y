package v1

import (
	uihandlers "github.com/brian-nunez/go-echo-starter-template/internal/handlers/v1/ui"
	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo) {
	e.GET("/", uihandlers.HomeHandler)

	v1Group := e.Group("/api/v1")
	v1Group.GET("/health", HealthHandler)
}
