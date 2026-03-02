package uihandlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/brian-nunez/ba11y/internal/auth"
	"github.com/brian-nunez/ba11y/internal/scans"
	"github.com/brian-nunez/ba11y/views/pages"
	"github.com/labstack/echo/v4"
)

type Handler struct {
	authService *auth.Service
	scanService *scans.Service
}

func NewHandler(authService *auth.Service, scanService *scans.Service) *Handler {
	return &Handler{
		authService: authService,
		scanService: scanService,
	}
}

func (h *Handler) Home(c echo.Context) error {
	return h.render(c, pages.Home(sessionView(c)))
}

func (h *Handler) ShowRegister(c echo.Context) error {
	if _, ok := getCurrentUser(c); ok {
		return c.Redirect(http.StatusSeeOther, "/scans/new")
	}

	return h.render(c, pages.AuthPage("Register", "/register", "Create account", "Already have an account?", "/login", "Sign in", "", strings.TrimSpace(c.QueryParam("email"))))
}

func (h *Handler) Register(c echo.Context) error {
	email := strings.TrimSpace(c.FormValue("email"))
	password := c.FormValue("password")

	_, err := h.authService.Register(c.Request().Context(), email, password)
	if err != nil {
		return h.render(c, pages.AuthPage("Register", "/register", "Create account", "Already have an account?", "/login", "Sign in", err.Error(), email))
	}

	_, sessionToken, err := h.authService.Login(c.Request().Context(), email, password)
	if err != nil {
		return h.render(c, pages.AuthPage("Register", "/register", "Create account", "Already have an account?", "/login", "Sign in", err.Error(), email))
	}

	setSessionCookie(c, sessionToken)
	return c.Redirect(http.StatusSeeOther, "/scans/new?success=Account+created")
}

func (h *Handler) ShowLogin(c echo.Context) error {
	if _, ok := getCurrentUser(c); ok {
		return c.Redirect(http.StatusSeeOther, "/scans/new")
	}

	return h.render(c, pages.AuthPage("Login", "/login", "Sign in", "Need an account?", "/register", "Create account", "", strings.TrimSpace(c.QueryParam("email"))))
}

func (h *Handler) Login(c echo.Context) error {
	email := strings.TrimSpace(c.FormValue("email"))
	password := c.FormValue("password")

	_, sessionToken, err := h.authService.Login(c.Request().Context(), email, password)
	if err != nil {
		return h.render(c, pages.AuthPage("Login", "/login", "Sign in", "Need an account?", "/register", "Create account", err.Error(), email))
	}

	setSessionCookie(c, sessionToken)
	return c.Redirect(http.StatusSeeOther, "/scans/new")
}

func (h *Handler) Logout(c echo.Context) error {
	sessionCookie, err := c.Cookie(sessionCookieName)
	if err == nil && sessionCookie != nil {
		_ = h.authService.Logout(c.Request().Context(), sessionCookie.Value)
	}
	clearSessionCookie(c)

	return c.Redirect(http.StatusSeeOther, "/login")
}

func (h *Handler) NewScan(c echo.Context) error {
	currentUser, ok := getCurrentUser(c)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	recentScans, err := h.scanService.ListScansForUser(c.Request().Context(), currentUser)
	if err != nil {
		return err
	}

	form := pages.DefaultScanForm()
	return h.render(c, pages.NewScanPage(sessionView(c), currentUser, recentScans, form, strings.TrimSpace(c.QueryParam("success")), strings.TrimSpace(c.QueryParam("error"))))
}

func (h *Handler) CreateScan(c echo.Context) error {
	currentUser, ok := getCurrentUser(c)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	scanType, err := scans.ParseScanType(c.FormValue("scan_type"))
	if err != nil {
		return h.renderNewScanWithError(c, currentUser, scanFormFromRequest(c), err.Error())
	}

	form := scanFormFromRequest(c)
	input := scans.CreateScanInput{
		OwnerUserID:           currentUser.ID,
		OwnerEmail:            currentUser.Email,
		Type:                  scanType,
		Target:                form.Target,
		Standard:              form.Standard,
		DeviceEmulation:       "Desktop",
		IncludeVisualContrast: false,
		IncludeSubPages:       false,
		IncludeBestPractices:  form.IncludeBestPractices,
	}

	scan, err := h.scanService.CreateScan(c.Request().Context(), currentUser, input)
	if err != nil {
		return h.renderNewScanWithError(c, currentUser, form, err.Error())
	}

	return c.Redirect(http.StatusSeeOther, "/scans/"+scan.ID+"/progress")
}

func (h *Handler) ScanHistory(c echo.Context) error {
	currentUser, ok := getCurrentUser(c)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	recentScans, err := h.scanService.ListScansForUser(c.Request().Context(), currentUser)
	if err != nil {
		return err
	}

	return h.render(c, pages.ScanHistoryPage(sessionView(c), currentUser, recentScans))
}

func (h *Handler) ScanProgress(c echo.Context) error {
	currentUser, ok := getCurrentUser(c)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	scan, err := h.scanService.GetScanForUser(c.Request().Context(), currentUser, c.Param("scanId"))
	if err != nil {
		if errors.Is(err, scans.ErrScanNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}
		if errors.Is(err, scans.ErrForbidden) {
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}
		return err
	}

	if scan.Status == scans.ScanStatusCompleted {
		return c.Redirect(http.StatusSeeOther, "/scans/"+scan.ID+"/report")
	}

	return h.render(c, pages.ScanProgressPage(sessionView(c), currentUser, scan))
}

func (h *Handler) ScanReport(c echo.Context) error {
	currentUser, ok := getCurrentUser(c)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	scan, err := h.scanService.GetScanForUser(c.Request().Context(), currentUser, c.Param("scanId"))
	if err != nil {
		if errors.Is(err, scans.ErrScanNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}
		if errors.Is(err, scans.ErrForbidden) {
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}
		return err
	}

	if scan.Status == scans.ScanStatusPending || scan.Status == scans.ScanStatusRunning {
		return c.Redirect(http.StatusSeeOther, "/scans/"+scan.ID+"/progress")
	}

	return h.render(c, pages.ScanReportPage(sessionView(c), currentUser, scan))
}

func (h *Handler) ExportScanReport(c echo.Context) error {
	currentUser, ok := getCurrentUser(c)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	scan, err := h.scanService.GetScanForUser(c.Request().Context(), currentUser, c.Param("scanId"))
	if err != nil {
		if errors.Is(err, scans.ErrScanNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}
		if errors.Is(err, scans.ErrForbidden) {
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}
		return err
	}

	payload := map[string]any{
		"exportedAt": time.Now().UTC().Format(time.RFC3339Nano),
		"scan":       scan,
	}

	if trimmed := strings.TrimSpace(scan.AxeRaw); trimmed != "" {
		var raw any
		if err := json.Unmarshal([]byte(trimmed), &raw); err == nil {
			payload["axe"] = raw
		}
		payload["axeRawJSON"] = trimmed
	}

	reportBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal export report: %w", err)
	}

	filename := fmt.Sprintf("scan-%s-report.json", scan.ID)
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	return c.Blob(http.StatusOK, echo.MIMEApplicationJSONCharsetUTF8, reportBytes)
}

func (h *Handler) CancelScan(c echo.Context) error {
	currentUser, ok := getCurrentUser(c)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	err := h.scanService.CancelScan(c.Request().Context(), currentUser, c.Param("scanId"))
	if err != nil {
		if errors.Is(err, scans.ErrScanNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}
		if errors.Is(err, scans.ErrForbidden) {
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}
		return err
	}

	return c.Redirect(http.StatusSeeOther, "/scans/new")
}

func (h *Handler) ScanStatus(c echo.Context) error {
	currentUser, ok := getCurrentUser(c)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
	}

	status, err := h.scanService.StatusForUser(c.Request().Context(), currentUser, c.Param("scanId"))
	if err != nil {
		if errors.Is(err, scans.ErrScanNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}
		if errors.Is(err, scans.ErrForbidden) {
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}
		return err
	}

	return c.JSON(http.StatusOK, status)
}

func (h *Handler) render(c echo.Context, component interface {
	Render(context.Context, io.Writer) error
}) error {
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTMLCharsetUTF8)
	return component.Render(context.Background(), c.Response().Writer)
}

func (h *Handler) renderNewScanWithError(c echo.Context, currentUser auth.User, form pages.ScanFormView, message string) error {
	recentScans, _ := h.scanService.ListScansForUser(c.Request().Context(), currentUser)
	return h.render(c, pages.NewScanPage(sessionView(c), currentUser, recentScans, form, "", message))
}

func sessionView(c echo.Context) pages.SessionView {
	user, ok := getCurrentUser(c)
	if !ok {
		return pages.SessionView{Authenticated: false}
	}

	return pages.SessionView{
		Authenticated: true,
		Email:         user.Email,
	}
}

func scanFormFromRequest(c echo.Context) pages.ScanFormView {
	form := pages.DefaultScanForm()
	form.SelectedType = strings.TrimSpace(c.FormValue("scan_type"))
	form.Target = strings.TrimSpace(c.FormValue("target"))
	form.Standard = strings.TrimSpace(c.FormValue("standard"))
	form.IncludeBestPractices = c.FormValue("include_best_practices") != ""

	if form.Target == "" {
		for _, key := range []string{"website_url"} {
			value := strings.TrimSpace(c.FormValue(key))
			if value != "" {
				form.Target = value
				break
			}
		}
	}

	if form.SelectedType == "" || !strings.EqualFold(form.SelectedType, string(scans.ScanTypeWebPage)) {
		form.SelectedType = string(scans.ScanTypeWebPage)
	}

	return form
}
