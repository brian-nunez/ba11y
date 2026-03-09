package scans

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/brian-nunez/bbaas-api/sdk/go/bbaas"
	worker "github.com/brian-nunez/task-orchestration"
	"github.com/playwright-community/playwright-go"
)

const playwrightGoModuleVersion = "v0.5700.1"

type scanTask struct {
	service *Service
	scanID  string
}

func (t *scanTask) Process(ctx context.Context, pc *worker.ProcessContext) error {
	if t.service == nil {
		return fmt.Errorf("scan service is nil")
	}

	t.service.startScan(t.scanID)
	t.service.setWorkerStatus(t.scanID, "running")

	scan, err := t.service.getScanForTask(t.scanID)
	if err != nil {
		return err
	}

	if strings.TrimSpace(t.service.apiToken) == "" {
		message := "BBAAS_API_TOKEN is required to run scans"
		t.service.failScan(t.scanID, message)
		return fmt.Errorf("%s", message)
	}

	t.service.updateStage(t.scanID, 18, "Connecting to Browser as a Service")
	spawned, err := t.service.bbaas.SpawnBrowser(ctx, bbaas.SpawnBrowserRequest{
		Headless:           ptr(true),
		IdleTimeoutSeconds: ptr(240),
	})
	if err != nil {
		t.service.failScan(t.scanID, "Could not create browser session from BBAAS")
		return fmt.Errorf("spawn browser from bbaas: %w", err)
	}
	if t.isCanceled() {
		t.service.setWorkerStatus(t.scanID, "canceled")
		return nil
	}

	t.service.attachBrowser(t.scanID, spawned.Browser.ID, spawned.Browser.CDPURL)
	defer func() {
		_ = t.service.bbaas.CloseBrowser(context.Background(), spawned.Browser.ID)
	}()

	_ = pc.Logger(fmt.Sprintf("Spawned browser %s", spawned.Browser.ID))

	t.service.updateStage(t.scanID, 28, "Booting Playwright runtime")
	pw, err := t.service.startPlaywrightRuntime()
	if err != nil {
		t.service.failScan(t.scanID, formatPlaywrightRuntimeFailure(err))
		return fmt.Errorf("run playwright: %w", err)
	}
	defer func() {
		_ = pw.Stop()
	}()

	t.service.updateStage(t.scanID, 36, "Connecting to browser through CDP")
	browser, err := pw.Chromium.ConnectOverCDP(spawned.Browser.CDPURL, playwright.BrowserTypeConnectOverCDPOptions{
		Timeout: playwright.Float(45000),
	})
	if err != nil {
		t.service.failScan(t.scanID, "Could not connect to browser over CDP")
		return fmt.Errorf("connect over cdp: %w", err)
	}
	defer func() {
		_ = browser.Close()
	}()

	if t.isCanceled() {
		t.service.setWorkerStatus(t.scanID, "canceled")
		return nil
	}

	t.service.updateStage(t.scanID, 46, "Preparing scan page")
	page, err := browser.NewPage()
	if err != nil {
		t.service.failScan(t.scanID, "Could not create browser page")
		return fmt.Errorf("create page: %w", err)
	}
	if err := preparePageForAxe(page); err != nil {
		t.service.failScan(t.scanID, "Could not configure scan runtime")
		return fmt.Errorf("prepare page for axe: %w", err)
	}

	if err := setViewportForDevice(page, scan.DeviceEmulation); err != nil {
		t.service.failScan(t.scanID, "Could not set browser viewport")
		return fmt.Errorf("set viewport: %w", err)
	}

	t.service.updateStage(t.scanID, 56, "Loading target asset")
	if err := loadTarget(page, scan); err != nil {
		if t.isCanceled() {
			t.service.setWorkerStatus(t.scanID, "canceled")
			return nil
		}
		t.service.failScan(t.scanID, "Could not load scan target")
		return fmt.Errorf("load target: %w", err)
	}

	if _, err := t.service.bbaas.KeepAliveBrowser(ctx, spawned.Browser.ID); err != nil {
		_ = pc.Logger(fmt.Sprintf("keepalive failed for browser %s: %v", spawned.Browser.ID, err))
	}

	if t.isCanceled() {
		t.service.setWorkerStatus(t.scanID, "canceled")
		return nil
	}

	t.service.updateStage(t.scanID, 70, "Running axe-core accessibility checks")
	auditResult, err := runAxeAudit(page, scan.Standard, scan.IncludeBestPractices)
	if err != nil {
		if t.isCanceled() {
			t.service.setWorkerStatus(t.scanID, "canceled")
			return nil
		}
		t.service.failScan(t.scanID, "Axe scan failed")
		return fmt.Errorf("run axe audit: %w", err)
	}

	t.service.updateStage(t.scanID, 88, "Capturing responsive evidence")
	evidence, err := captureEvidence(page, scan.ID)
	if err != nil {
		_ = pc.Logger(fmt.Sprintf("evidence capture failed for scan %s: %v", scan.ID, err))
		evidence = defaultEvidence()
	}
	t.service.setEvidence(t.scanID, evidence)

	t.service.updateStage(t.scanID, 96, "Finalizing report")
	t.service.completeScan(t.scanID, auditResult.Findings, auditResult.RawJSON)
	t.service.setWorkerStatus(t.scanID, "completed")

	return nil
}

func (t *scanTask) isCanceled() bool {
	return t.service.isCanceled(t.scanID)
}

func ptr[T any](value T) *T {
	return &value
}

func (s *Service) startPlaywrightRuntime() (*playwright.Playwright, error) {
	return playwright.Run()
}

func formatPlaywrightRuntimeFailure(err error) string {
	const maxPlaywrightFailureMessageLength = 220

	if err == nil {
		return "Could not start Playwright runtime"
	}

	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "Could not start Playwright runtime"
	}

	message = strings.ReplaceAll(message, "\n", " ")
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > maxPlaywrightFailureMessageLength {
		message = message[:maxPlaywrightFailureMessageLength] + "..."
	}

	if errors.Is(err, ErrInvalidTarget) {
		return "Could not start Playwright runtime"
	}

	if strings.Contains(message, "please install the driver") {
		return fmt.Sprintf(
			"Could not start Playwright runtime: install the pinned driver with `go run github.com/playwright-community/playwright-go/cmd/playwright@%s --version`",
			playwrightGoModuleVersion,
		)
	}

	return "Could not start Playwright runtime: " + message
}
