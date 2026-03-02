package scans

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/brian-nunez/bbaas-api/sdk/go/bbaas"
	worker "github.com/brian-nunez/task-orchestration"
)

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
		IdleTimeoutSeconds: ptr(180),
	})
	if err != nil {
		t.service.failScan(t.scanID, "Could not create browser session from BBAAS")
		return fmt.Errorf("spawn browser from bbaas: %w", err)
	}

	t.service.attachBrowser(t.scanID, spawned.Browser.ID, spawned.Browser.CDPURL)
	defer func() {
		_ = t.service.bbaas.CloseBrowser(context.Background(), spawned.Browser.ID)
	}()

	_ = pc.Logger(fmt.Sprintf("Spawned browser %s", spawned.Browser.ID))

	steps := stagePlan(scan.Type)
	progress := 28
	for _, step := range steps {
		if t.service.isCanceled(t.scanID) {
			t.service.setWorkerStatus(t.scanID, "canceled")
			return nil
		}

		t.service.updateStage(t.scanID, progress, step)
		if err := sleepOrCancel(ctx, 1200*time.Millisecond); err != nil {
			t.service.failScan(t.scanID, "Scan canceled")
			return err
		}
		progress += 16
	}

	if _, err := t.service.bbaas.KeepAliveBrowser(ctx, spawned.Browser.ID); err != nil {
		_ = pc.Logger(fmt.Sprintf("Keepalive failed for browser %s: %v", spawned.Browser.ID, err))
	}

	t.service.updateStage(t.scanID, 92, "Preparing report")
	if err := sleepOrCancel(ctx, 600*time.Millisecond); err != nil {
		t.service.failScan(t.scanID, "Scan canceled")
		return err
	}

	t.service.completeScan(t.scanID, mockFindings(scan.Type, scan.Standard))
	t.service.setWorkerStatus(t.scanID, "completed")

	return nil
}

func stagePlan(scanType ScanType) []string {
	switch scanType {
	case ScanTypeWebPage:
		return []string{
			"Loading page and resolving dynamic content",
			"Running semantic landmark checks",
			"Auditing keyboard navigation and focus order",
			"Evaluating color contrast and text alternatives",
		}
	case ScanTypeEmail:
		return []string{
			"Rendering email markup in browser context",
			"Analyzing heading hierarchy and link purpose",
			"Checking color contrast for brand templates",
			"Validating responsive email structure",
		}
	case ScanTypePDF:
		return []string{
			"Rendering document pages in browser context",
			"Evaluating reading order and heading structure",
			"Checking text alternatives for embedded media",
			"Auditing contrast and annotation clarity",
		}
	case ScanTypeJourney:
		return []string{
			"Bootstrapping multi-step journey execution",
			"Running keyboard-only path analysis",
			"Checking modal and form accessibility states",
			"Capturing path-level compliance evidence",
		}
	default:
		return []string{
			"Analyzing digital asset structure",
			"Running WCAG rule evaluation",
			"Preparing accessibility evidence",
			"Building report",
		}
	}
}

func mockFindings(scanType ScanType, standard string) []Finding {
	targetName := "interface"
	switch scanType {
	case ScanTypeWebPage:
		targetName = "webpage"
	case ScanTypeEmail:
		targetName = "email template"
	case ScanTypePDF:
		targetName = "PDF document"
	case ScanTypeJourney:
		targetName = "user journey"
	}

	return []Finding{
		{
			ID:          "f-1",
			Title:       "Missing Alt Text",
			Description: fmt.Sprintf("Images in this %s must include alternate text describing purpose.", targetName),
			Snippet:     `<img src="/assets/hero-banner.jpg" class="w-full h-auto">`,
			Severity:    SeverityCritical,
			Standard:    standard,
			Criterion:   "Success Criterion 1.1.1",
			Method:      MethodAutomated,
		},
		{
			ID:          "f-2",
			Title:       "Insufficient Color Contrast",
			Description: "Foreground and background colors require a minimum contrast ratio of 4.5:1.",
			Snippet:     `<button class="text-[#888] bg-white">Cancel</button>`,
			Severity:    SeveritySerious,
			Standard:    standard,
			Criterion:   "Success Criterion 1.4.3",
			Method:      MethodAutomated,
		},
		{
			ID:          "f-3",
			Title:       "Form Element Missing Label",
			Description: "Each form field requires an associated visible or assistive label.",
			Snippet:     `<input type="email" id="newsletter-email" />`,
			Severity:    SeverityCritical,
			Standard:    standard,
			Criterion:   "Success Criterion 1.3.1",
			Method:      MethodAutomated,
		},
		{
			ID:          "f-4",
			Title:       "Interactive Element Not Keyboard Focusable",
			Description: "Custom controls must support keyboard focus and semantic roles.",
			Snippet:     `<div class="btn-submit" onclick="submit()">Send</div>`,
			Severity:    SeverityModerate,
			Standard:    standard,
			Criterion:   "Success Criterion 2.1.1",
			Method:      MethodManual,
		},
	}
}

func sleepOrCancel(ctx context.Context, wait time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

func ptr[T any](value T) *T {
	return &value
}
