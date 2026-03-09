package v1

import (
	"github.com/brian-nunez/ba11y/internal/auth"
	uihandlers "github.com/brian-nunez/ba11y/internal/handlers/v1/ui"
	"github.com/brian-nunez/ba11y/internal/scans"
	"github.com/labstack/echo/v4"
)

type Dependencies struct {
	AuthService *auth.Service
	ScanService *scans.Service
}

func RegisterRoutes(e *echo.Echo, dependencies Dependencies) {
	e.Use(uihandlers.SessionMiddleware(dependencies.AuthService))

	handler := uihandlers.NewHandler(dependencies.AuthService, dependencies.ScanService)

	e.GET("/", handler.Home)
	e.GET("/register", handler.ShowRegister, uihandlers.RequireGuest)
	e.POST("/register", handler.Register, uihandlers.RequireGuest)
	e.GET("/login", handler.ShowLogin, uihandlers.RequireGuest)
	e.POST("/login", handler.Login, uihandlers.RequireGuest)
	e.POST("/logout", handler.Logout, uihandlers.RequireAuth)

	e.GET("/scans", handler.ScanHistory, uihandlers.RequireAuth)
	e.GET("/scans/recurring", handler.RecurringHistory, uihandlers.RequireAuth)
	e.GET("/scans/new", handler.NewScan, uihandlers.RequireAuth)
	e.POST("/scans", handler.CreateScan, uihandlers.RequireAuth)
	e.GET("/scans/:scanId/recurring", handler.ScanRecurring, uihandlers.RequireAuth)
	e.POST("/scans/:scanId/recurring", handler.CreateRecurringScanFromReport, uihandlers.RequireAuth)
	e.POST("/scans/recurring/:recurringScanId/update", handler.UpdateRecurringScan, uihandlers.RequireAuth)
	e.POST("/scans/recurring/:recurringScanId/enable", handler.EnableRecurringScan, uihandlers.RequireAuth)
	e.POST("/scans/recurring/:recurringScanId/disable", handler.DisableRecurringScan, uihandlers.RequireAuth)
	e.POST("/scans/recurring/:recurringScanId/stop", handler.StopRecurringScan, uihandlers.RequireAuth)
	e.POST("/scans/recurring/:recurringScanId/delete", handler.DeleteRecurringScan, uihandlers.RequireAuth)
	e.POST("/scans/:scanId/cancel", handler.CancelScan, uihandlers.RequireAuth)
	e.GET("/scans/:scanId/progress", handler.ScanProgress, uihandlers.RequireAuth)
	e.GET("/scans/:scanId/report", handler.ScanReport, uihandlers.RequireAuth)
	e.GET("/scans/:scanId/export", handler.ExportScanReport, uihandlers.RequireAuth)

	v1Group := e.Group("/api/v1")
	v1Group.GET("/health", HealthHandler)
	v1Group.GET("/scans/:scanId/status", handler.ScanStatus, uihandlers.RequireAuthAPI)
	v1Group.POST("/recurring-scans/webhook", handler.RecurringScanWebhook)
	v1Group.POST("/recurring-scans/webhook/", handler.RecurringScanWebhook)
	v1Group.POST("/scans/recurring/webhook", handler.RecurringScanWebhook)
	v1Group.POST("/scans/recurring/webhook/", handler.RecurringScanWebhook)

	e.POST("/recurring-scans/webhook", handler.RecurringScanWebhook)
	e.POST("/recurring-scans/webhook/", handler.RecurringScanWebhook)
}
