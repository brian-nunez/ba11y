package scans

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/brian-nunez/ba11y/internal/auth"
	"github.com/brian-nunez/ba11y/internal/authorization"
	"github.com/brian-nunez/bbaas-api/sdk/go/bbaas"
	btick "github.com/brian-nunez/btick/sdk/go/scheduler"
	worker "github.com/brian-nunez/task-orchestration"
)

var (
	ErrForbidden                = errors.New("forbidden")
	ErrScanNotFound             = errors.New("scan not found")
	ErrInvalidTarget            = errors.New("target is required")
	ErrInvalidScanType          = errors.New("invalid scan type")
	ErrRecurringScanNotFound    = errors.New("recurring scan not found")
	ErrRecurringScanInactive    = errors.New("recurring scan is not enabled")
	ErrInvalidRecurringSchedule = errors.New("invalid recurring schedule")
	ErrRecurringFeatureDisabled = errors.New("recurring scans are not configured")
	ErrInvalidWebhookSecret     = errors.New("invalid webhook secret")
)

type Config struct {
	BBAASBaseURL       string
	BBAASAPIToken      string
	BTickBaseURL       string
	BTickAPIKey        string
	BTickWebhookURL    string
	BTickWebhookSecret string
	WorkerConcurrency  int
	WorkerLogPath      string
	WorkerDatabasePath string
}

type Service struct {
	mu                   sync.RWMutex
	scansByID            map[string]*Scan
	orderedScanIDs       []string
	recurringByID        map[string]*RecurringScan
	orderedRecurringIDs  []string
	btickWebhookURL      string
	btickWebhookSecret   string
	btickAPIKeyAvailable bool

	db         *sql.DB
	authorizer *authorization.ScanAuthorizer
	bbaas      *bbaas.Client
	btick      *btick.Client
	apiToken   string
	workerPool *worker.WorkerPool
	now        func() time.Time
}

func NewService(config Config, authorizer *authorization.ScanAuthorizer, db *sql.DB) (*Service, error) {
	if db == nil {
		return nil, fmt.Errorf("scan database is nil")
	}

	baseURL := strings.TrimSpace(config.BBAASBaseURL)
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8080"
	}

	client, err := bbaas.NewClient(baseURL, bbaas.WithAPIToken(strings.TrimSpace(config.BBAASAPIToken)))
	if err != nil {
		return nil, fmt.Errorf("create bbaas client: %w", err)
	}

	var btickClient *btick.Client
	btickBaseURL := strings.TrimSpace(config.BTickBaseURL)
	if btickBaseURL != "" {
		btickClient, err = btick.NewClient(btickBaseURL, btick.WithAPIKey(strings.TrimSpace(config.BTickAPIKey)))
		if err != nil {
			return nil, fmt.Errorf("create btick client: %w", err)
		}
	}

	service := &Service{
		scansByID:            make(map[string]*Scan),
		orderedScanIDs:       make([]string, 0),
		recurringByID:        make(map[string]*RecurringScan),
		orderedRecurringIDs:  make([]string, 0),
		db:                   db,
		authorizer:           authorizer,
		bbaas:                client,
		btick:                btickClient,
		apiToken:             strings.TrimSpace(config.BBAASAPIToken),
		now:                  time.Now,
		btickWebhookURL:      strings.TrimSpace(config.BTickWebhookURL),
		btickWebhookSecret:   strings.TrimSpace(config.BTickWebhookSecret),
		btickAPIKeyAvailable: strings.TrimSpace(config.BTickAPIKey) != "",
	}

	if err := service.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("ensure scan schema: %w", err)
	}

	if err := service.loadScans(context.Background()); err != nil {
		return nil, fmt.Errorf("load scans from sqlite: %w", err)
	}

	if err := service.loadRecurringScans(context.Background()); err != nil {
		return nil, fmt.Errorf("load recurring scans from sqlite: %w", err)
	}

	concurrency := config.WorkerConcurrency
	if concurrency <= 0 {
		concurrency = 3
	}

	logPath := strings.TrimSpace(config.WorkerLogPath)
	if logPath == "" {
		logPath = "./data/logs"
	}

	databasePath := strings.TrimSpace(config.WorkerDatabasePath)
	if databasePath == "" {
		databasePath = "./data/ba11y.db"
	}

	pool := worker.NewWorkerPool(worker.WorkerPoolConfig{
		Concurrency:  concurrency,
		LogPath:      logPath,
		DatabasePath: databasePath,
	})
	if err := pool.Start(); err != nil {
		return nil, fmt.Errorf("start worker pool: %w", err)
	}
	service.workerPool = pool

	return service, nil
}

func (s *Service) Shutdown() {
	if s.workerPool != nil {
		s.workerPool.Stop()
	}
}

func (s *Service) CreateScan(ctx context.Context, actor auth.User, input CreateScanInput) (Scan, error) {
	if input.OwnerUserID == "" {
		input.OwnerUserID = actor.ID
	}
	if input.OwnerEmail == "" {
		input.OwnerEmail = actor.Email
	}
	if input.Type == "" {
		return Scan{}, ErrInvalidScanType
	}
	if strings.TrimSpace(input.Target) == "" {
		return Scan{}, ErrInvalidTarget
	}

	resource := authorization.ScanResource{OwnerUserID: input.OwnerUserID}
	if !s.authorizer.Can(actor, resource, "scans.create") {
		return Scan{}, ErrForbidden
	}

	now := s.now().UTC()
	scanID, err := generateToken("scan", 12)
	if err != nil {
		return Scan{}, fmt.Errorf("generate scan id: %w", err)
	}

	standard := strings.TrimSpace(input.Standard)
	if standard == "" {
		standard = "WCAG 2.1 Level AA"
	}

	device := strings.TrimSpace(input.DeviceEmulation)
	if device == "" {
		device = "Desktop"
	}

	scan := &Scan{
		ID:                    scanID,
		OwnerUserID:           input.OwnerUserID,
		RequestedByEmail:      input.OwnerEmail,
		RecurringScanID:       strings.TrimSpace(input.RecurringScanID),
		Type:                  input.Type,
		Target:                strings.TrimSpace(input.Target),
		Standard:              standard,
		DeviceEmulation:       device,
		IncludeVisualContrast: input.IncludeVisualContrast,
		IncludeSubPages:       input.IncludeSubPages,
		IncludeBestPractices:  input.IncludeBestPractices,
		Status:                ScanStatusPending,
		Progress:              6,
		Stage:                 "Queued for scanning",
		CreatedAt:             now,
		Evidence:              defaultEvidence(),
	}

	s.mu.Lock()
	s.scansByID[scan.ID] = scan
	s.orderedScanIDs = append([]string{scan.ID}, s.orderedScanIDs...)
	if err := s.persistScanLocked(scan); err != nil {
		delete(s.scansByID, scan.ID)
		s.orderedScanIDs = removeScanID(s.orderedScanIDs, scan.ID)
		s.mu.Unlock()
		return Scan{}, fmt.Errorf("persist new scan: %w", err)
	}
	s.mu.Unlock()

	taskInfo, err := s.workerPool.AddTask(&scanTask{service: s, scanID: scan.ID})
	if err != nil {
		s.failScan(scan.ID, "Failed to enqueue scan task")
		return Scan{}, fmt.Errorf("enqueue scan task: %w", err)
	}

	s.mu.Lock()
	stored := s.scansByID[scan.ID]
	if stored != nil {
		stored.TaskProcessID = taskInfo.ProcessID
		stored.WorkerStatus = taskInfo.Status
		if err := s.persistScanLocked(stored); err != nil {
			s.mu.Unlock()
			return Scan{}, fmt.Errorf("persist scan task metadata: %w", err)
		}
	}
	out := s.cloneScan(stored)
	s.mu.Unlock()

	return out, nil
}

func (s *Service) ListScansForUser(_ context.Context, actor auth.User) ([]Scan, error) {
	if !s.authorizer.Can(actor, authorization.ScanResource{OwnerUserID: actor.ID}, "scans.list") {
		return nil, ErrForbidden
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Scan, 0)
	for _, scanID := range s.orderedScanIDs {
		scan := s.scansByID[scanID]
		if scan == nil {
			continue
		}
		if actor.IsAdmin() || scan.OwnerUserID == actor.ID {
			out = append(out, s.cloneScan(scan))
		}
	}

	return out, nil
}

func (s *Service) GetScanForUser(_ context.Context, actor auth.User, scanID string) (Scan, error) {
	s.mu.RLock()
	scan := s.scansByID[scanID]
	s.mu.RUnlock()

	if scan == nil {
		return Scan{}, ErrScanNotFound
	}

	resource := authorization.ScanResource{OwnerUserID: scan.OwnerUserID}
	if !s.authorizer.Can(actor, resource, "scans.read") {
		return Scan{}, ErrForbidden
	}

	return s.cloneScan(scan), nil
}

func (s *Service) CancelScan(_ context.Context, actor auth.User, scanID string) error {
	s.mu.Lock()
	scan := s.scansByID[scanID]
	if scan == nil {
		s.mu.Unlock()
		return ErrScanNotFound
	}

	resource := authorization.ScanResource{OwnerUserID: scan.OwnerUserID}
	if !s.authorizer.Can(actor, resource, "scans.cancel") {
		s.mu.Unlock()
		return ErrForbidden
	}

	if isTerminalStatus(scan.Status) {
		s.mu.Unlock()
		return nil
	}

	now := s.now().UTC()
	scan.Status = ScanStatusCanceled
	scan.Progress = max(scan.Progress, 10)
	scan.Stage = "Scan canceled"
	scan.ErrorMessage = "Canceled by user"
	scan.FinishedAt = &now
	if err := s.persistScanLocked(scan); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("persist canceled scan: %w", err)
	}
	browserID := scan.BrowserID
	s.mu.Unlock()

	if browserID != "" {
		_ = s.bbaas.CloseBrowser(context.Background(), browserID)
	}

	return nil
}

func (s *Service) StatusForUser(ctx context.Context, actor auth.User, scanID string) (StatusPayload, error) {
	scan, err := s.GetScanForUser(ctx, actor, scanID)
	if err != nil {
		return StatusPayload{}, err
	}

	payload := StatusPayload{
		ID:               scan.ID,
		Status:           scan.Status,
		Progress:         scan.Progress,
		Stage:            scan.Stage,
		ErrorMessage:     scan.ErrorMessage,
		TaskProcessID:    scan.TaskProcessID,
		WorkerStatus:     scan.WorkerStatus,
		EstimatedSeconds: estimateSecondsRemaining(scan.Status, scan.Progress),
	}

	if s.workerPool != nil && scan.TaskProcessID != "" {
		taskInfo, err := s.workerPool.GetTaskByProcessId(worker.GetTaskByProcessIdParams{
			ProcessId: scan.TaskProcessID,
		})
		if err == nil && taskInfo != nil {
			payload.WorkerStatus = taskInfo.Status
		}
	}

	return payload, nil
}

func (s *Service) startScan(scanID string) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	scan := s.scansByID[scanID]
	if scan == nil || isTerminalStatus(scan.Status) {
		return
	}

	scan.Status = ScanStatusRunning
	scan.Progress = max(scan.Progress, 12)
	scan.Stage = "Initializing scan environment"
	scan.StartedAt = &now
	_ = s.persistScanLocked(scan)
}

func (s *Service) updateStage(scanID string, progress int, stage string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	scan := s.scansByID[scanID]
	if scan == nil || isTerminalStatus(scan.Status) {
		return
	}

	scan.Progress = min(max(progress, 0), 99)
	scan.Stage = stage
	_ = s.persistScanLocked(scan)
}

func (s *Service) setWorkerStatus(scanID string, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	scan := s.scansByID[scanID]
	if scan == nil {
		return
	}

	scan.WorkerStatus = status
	_ = s.persistScanLocked(scan)
}

func (s *Service) attachBrowser(scanID string, browserID string, cdpURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	scan := s.scansByID[scanID]
	if scan == nil {
		return
	}

	scan.BrowserID = browserID
	scan.BrowserCDPURL = cdpURL
	_ = s.persistScanLocked(scan)
}

func (s *Service) failScan(scanID string, reason string) {
	now := s.now().UTC()
	message := strings.TrimSpace(reason)
	if message == "" {
		message = "Scan failed"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	scan := s.scansByID[scanID]
	if scan == nil {
		return
	}

	scan.Status = ScanStatusFailed
	scan.Stage = "Failed"
	scan.Progress = min(max(scan.Progress, 15), 100)
	scan.ErrorMessage = message
	scan.FinishedAt = &now
	_ = s.persistScanLocked(scan)
}

func (s *Service) completeScan(scanID string, findings []Finding, axeRaw string) {
	now := s.now().UTC()
	summary := summarizeFindings(findings)

	s.mu.Lock()
	defer s.mu.Unlock()

	scan := s.scansByID[scanID]
	if scan == nil {
		return
	}

	scan.Status = ScanStatusCompleted
	scan.Progress = 100
	scan.Stage = "Scan complete"
	scan.Findings = findings
	scan.Summary = summary
	scan.AxeRaw = strings.TrimSpace(axeRaw)
	scan.FinishedAt = &now
	scan.ErrorMessage = ""
	_ = s.persistScanLocked(scan)
}

func (s *Service) setEvidence(scanID string, evidence Evidence) {
	s.mu.Lock()
	defer s.mu.Unlock()

	scan := s.scansByID[scanID]
	if scan == nil {
		return
	}

	scan.Evidence = evidence
	_ = s.persistScanLocked(scan)
}

func (s *Service) getScanForTask(scanID string) (Scan, error) {
	s.mu.RLock()
	scan := s.scansByID[scanID]
	s.mu.RUnlock()

	if scan == nil {
		return Scan{}, ErrScanNotFound
	}

	return s.cloneScan(scan), nil
}

func (s *Service) isCanceled(scanID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scan := s.scansByID[scanID]
	if scan == nil {
		return true
	}

	return scan.Status == ScanStatusCanceled
}

func (s *Service) cloneScan(scan *Scan) Scan {
	if scan == nil {
		return Scan{}
	}

	copyScan := *scan
	copyScan.Findings = cloneFindings(scan.Findings)
	copyScan.AxeRaw = scan.AxeRaw
	if scan.StartedAt != nil {
		started := *scan.StartedAt
		copyScan.StartedAt = &started
	}
	if scan.FinishedAt != nil {
		finished := *scan.FinishedAt
		copyScan.FinishedAt = &finished
	}

	return copyScan
}

func (s *Service) ensureSchema(ctx context.Context) error {
	statements := []string{
		`
		CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			owner_user_id TEXT NOT NULL,
			requested_by_email TEXT NOT NULL,
			recurring_scan_id TEXT NOT NULL DEFAULT '',
			type TEXT NOT NULL,
			target TEXT NOT NULL,
			standard TEXT NOT NULL,
			device_emulation TEXT NOT NULL,
			include_visual_contrast INTEGER NOT NULL,
			include_sub_pages INTEGER NOT NULL,
			include_best_practices INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			progress INTEGER NOT NULL,
			stage TEXT NOT NULL,
			error_message TEXT NOT NULL,
			task_process_id TEXT NOT NULL,
			worker_status TEXT NOT NULL,
			browser_id TEXT NOT NULL,
			browser_cdp_url TEXT NOT NULL,
			created_at TEXT NOT NULL,
			started_at TEXT,
			finished_at TEXT,
			summary_total INTEGER NOT NULL,
			summary_critical INTEGER NOT NULL,
			summary_serious INTEGER NOT NULL,
			summary_moderate INTEGER NOT NULL,
			axe_raw_json TEXT NOT NULL DEFAULT '',
			evidence_desktop_image_url TEXT NOT NULL,
			evidence_tablet_image_url TEXT NOT NULL,
			evidence_mobile_image_url TEXT NOT NULL,
			evidence_recording_image_url TEXT NOT NULL
		);
		`,
		`CREATE INDEX IF NOT EXISTS idx_scans_owner_user_id ON scans(owner_user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);`,
		`
		CREATE TABLE IF NOT EXISTS scan_findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id TEXT NOT NULL,
			finding_id TEXT NOT NULL,
			rule_id TEXT NOT NULL DEFAULT '',
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			snippet TEXT NOT NULL,
			node_html TEXT NOT NULL DEFAULT '',
			failure_summary TEXT NOT NULL DEFAULT '',
			severity TEXT NOT NULL,
			impact TEXT NOT NULL DEFAULT '',
			standard TEXT NOT NULL,
			criterion TEXT NOT NULL,
			method TEXT NOT NULL,
			help_url TEXT NOT NULL DEFAULT '',
			tags_json TEXT NOT NULL DEFAULT '[]',
			targets_json TEXT NOT NULL DEFAULT '[]',
			raw_json TEXT NOT NULL DEFAULT '{}',
			sort_order INTEGER NOT NULL,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);
		`,
		`CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_order ON scan_findings(scan_id, sort_order);`,
		`
		CREATE TABLE IF NOT EXISTS recurring_scans (
			id TEXT PRIMARY KEY,
			source_scan_id TEXT NOT NULL DEFAULT '',
			owner_user_id TEXT NOT NULL,
			requested_by_email TEXT NOT NULL,
			type TEXT NOT NULL,
			target TEXT NOT NULL,
			standard TEXT NOT NULL,
			include_best_practices INTEGER NOT NULL DEFAULT 0,
			frequency TEXT NOT NULL,
			cron_expression TEXT NOT NULL,
			timezone TEXT NOT NULL,
			minute INTEGER NOT NULL,
			hour_of_day INTEGER NOT NULL,
			day_of_week INTEGER NOT NULL,
			day_of_month INTEGER NOT NULL,
			btick_job_id TEXT NOT NULL,
			state TEXT NOT NULL,
			last_triggered_at TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			stopped_at TEXT
		);
		`,
		`CREATE INDEX IF NOT EXISTS idx_recurring_scans_owner_user_id ON recurring_scans(owner_user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_recurring_scans_state ON recurring_scans(state);`,
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}

	if err := s.ensureScansColumn(ctx, "include_best_practices", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureScansColumn(ctx, "recurring_scan_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureScansColumn(ctx, "axe_raw_json", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureScanFindingsColumn(ctx, "rule_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureScanFindingsColumn(ctx, "node_html", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureScanFindingsColumn(ctx, "failure_summary", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureScanFindingsColumn(ctx, "impact", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureScanFindingsColumn(ctx, "help_url", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureScanFindingsColumn(ctx, "tags_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := s.ensureScanFindingsColumn(ctx, "targets_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := s.ensureScanFindingsColumn(ctx, "raw_json", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return err
	}
	if err := s.ensureRecurringScansColumn(ctx, "include_best_practices", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureRecurringScansColumn(ctx, "source_scan_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureRecurringScansColumn(ctx, "last_triggered_at", "TEXT"); err != nil {
		return err
	}
	if err := s.ensureRecurringScansColumn(ctx, "stopped_at", "TEXT"); err != nil {
		return err
	}

	return nil
}

func (s *Service) loadScans(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	scanRows, err := s.db.QueryContext(ctx, `
		SELECT
			id,
			owner_user_id,
			requested_by_email,
			recurring_scan_id,
			type,
			target,
			standard,
			device_emulation,
			include_visual_contrast,
			include_sub_pages,
			include_best_practices,
			status,
			progress,
			stage,
			error_message,
			task_process_id,
			worker_status,
			browser_id,
			browser_cdp_url,
			created_at,
			started_at,
			finished_at,
			summary_total,
			summary_critical,
			summary_serious,
			summary_moderate,
			axe_raw_json,
			evidence_desktop_image_url,
			evidence_tablet_image_url,
			evidence_mobile_image_url,
			evidence_recording_image_url
		FROM scans
		ORDER BY created_at DESC
	`)
	if err != nil {
		return fmt.Errorf("query scans: %w", err)
	}
	defer scanRows.Close()

	s.scansByID = make(map[string]*Scan)
	s.orderedScanIDs = make([]string, 0)

	for scanRows.Next() {
		var (
			includeVisualContrast int
			includeSubPages       int
			includeBestPractices  int
			startedAt             sql.NullString
			finishedAt            sql.NullString
			createdAtRaw          string
			scan                  Scan
		)

		err := scanRows.Scan(
			&scan.ID,
			&scan.OwnerUserID,
			&scan.RequestedByEmail,
			&scan.RecurringScanID,
			&scan.Type,
			&scan.Target,
			&scan.Standard,
			&scan.DeviceEmulation,
			&includeVisualContrast,
			&includeSubPages,
			&includeBestPractices,
			&scan.Status,
			&scan.Progress,
			&scan.Stage,
			&scan.ErrorMessage,
			&scan.TaskProcessID,
			&scan.WorkerStatus,
			&scan.BrowserID,
			&scan.BrowserCDPURL,
			&createdAtRaw,
			&startedAt,
			&finishedAt,
			&scan.Summary.Total,
			&scan.Summary.Critical,
			&scan.Summary.Serious,
			&scan.Summary.Moderate,
			&scan.AxeRaw,
			&scan.Evidence.DesktopImageURL,
			&scan.Evidence.TabletImageURL,
			&scan.Evidence.MobileImageURL,
			&scan.Evidence.RecordingImageURL,
		)
		if err != nil {
			return fmt.Errorf("scan row: %w", err)
		}

		scan.CreatedAt, err = parseStoreTime(createdAtRaw)
		if err != nil {
			return fmt.Errorf("parse scan created_at: %w", err)
		}
		scan.StartedAt, err = parseNullableStoreTime(startedAt)
		if err != nil {
			return fmt.Errorf("parse scan started_at: %w", err)
		}
		scan.FinishedAt, err = parseNullableStoreTime(finishedAt)
		if err != nil {
			return fmt.Errorf("parse scan finished_at: %w", err)
		}

		scan.IncludeVisualContrast = intToBool(includeVisualContrast)
		scan.IncludeSubPages = intToBool(includeSubPages)
		scan.IncludeBestPractices = intToBool(includeBestPractices)
		scan.Evidence = normalizeEvidence(scan.Evidence)
		scan.Findings = make([]Finding, 0)

		scanCopy := scan
		s.scansByID[scan.ID] = &scanCopy
		s.orderedScanIDs = append(s.orderedScanIDs, scan.ID)
	}

	if err := scanRows.Err(); err != nil {
		return fmt.Errorf("iterate scan rows: %w", err)
	}

	findingsRows, err := s.db.QueryContext(ctx, `
		SELECT
			scan_id,
			finding_id,
			rule_id,
			title,
			description,
			snippet,
			node_html,
			failure_summary,
			severity,
			impact,
			standard,
			criterion,
			method,
			help_url,
			tags_json,
			targets_json,
			raw_json
		FROM scan_findings
		ORDER BY scan_id, sort_order
	`)
	if err != nil {
		return fmt.Errorf("query scan findings: %w", err)
	}
	defer findingsRows.Close()

	for findingsRows.Next() {
		var (
			scanID      string
			finding     Finding
			tagsJSON    string
			targetsJSON string
		)

		if err := findingsRows.Scan(
			&scanID,
			&finding.ID,
			&finding.RuleID,
			&finding.Title,
			&finding.Description,
			&finding.Snippet,
			&finding.NodeHTML,
			&finding.Failure,
			&finding.Severity,
			&finding.Impact,
			&finding.Standard,
			&finding.Criterion,
			&finding.Method,
			&finding.HelpURL,
			&tagsJSON,
			&targetsJSON,
			&finding.RawJSON,
		); err != nil {
			return fmt.Errorf("scan finding row: %w", err)
		}

		finding.Tags = parseStringJSONArray(tagsJSON)
		finding.Targets = parseStringJSONArray(targetsJSON)

		scan := s.scansByID[scanID]
		if scan == nil {
			continue
		}

		scan.Findings = append(scan.Findings, finding)
	}

	if err := findingsRows.Err(); err != nil {
		return fmt.Errorf("iterate findings rows: %w", err)
	}

	return nil
}

func (s *Service) persistScanLocked(scan *Scan) error {
	if scan == nil {
		return nil
	}

	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin scan transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`
		INSERT INTO scans (
			id,
			owner_user_id,
			requested_by_email,
			recurring_scan_id,
			type,
			target,
			standard,
			device_emulation,
			include_visual_contrast,
			include_sub_pages,
			include_best_practices,
			status,
			progress,
			stage,
			error_message,
			task_process_id,
			worker_status,
			browser_id,
			browser_cdp_url,
			created_at,
			started_at,
			finished_at,
			summary_total,
			summary_critical,
			summary_serious,
			summary_moderate,
			axe_raw_json,
			evidence_desktop_image_url,
			evidence_tablet_image_url,
			evidence_mobile_image_url,
			evidence_recording_image_url
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			owner_user_id = excluded.owner_user_id,
			requested_by_email = excluded.requested_by_email,
			recurring_scan_id = excluded.recurring_scan_id,
			type = excluded.type,
			target = excluded.target,
			standard = excluded.standard,
			device_emulation = excluded.device_emulation,
			include_visual_contrast = excluded.include_visual_contrast,
			include_sub_pages = excluded.include_sub_pages,
			include_best_practices = excluded.include_best_practices,
			status = excluded.status,
			progress = excluded.progress,
			stage = excluded.stage,
			error_message = excluded.error_message,
			task_process_id = excluded.task_process_id,
			worker_status = excluded.worker_status,
			browser_id = excluded.browser_id,
			browser_cdp_url = excluded.browser_cdp_url,
			created_at = excluded.created_at,
			started_at = excluded.started_at,
			finished_at = excluded.finished_at,
			summary_total = excluded.summary_total,
			summary_critical = excluded.summary_critical,
			summary_serious = excluded.summary_serious,
			summary_moderate = excluded.summary_moderate,
			axe_raw_json = excluded.axe_raw_json,
			evidence_desktop_image_url = excluded.evidence_desktop_image_url,
			evidence_tablet_image_url = excluded.evidence_tablet_image_url,
			evidence_mobile_image_url = excluded.evidence_mobile_image_url,
			evidence_recording_image_url = excluded.evidence_recording_image_url
	`,
		scan.ID,
		scan.OwnerUserID,
		scan.RequestedByEmail,
		scan.RecurringScanID,
		string(scan.Type),
		scan.Target,
		scan.Standard,
		scan.DeviceEmulation,
		boolToInt(scan.IncludeVisualContrast),
		boolToInt(scan.IncludeSubPages),
		boolToInt(scan.IncludeBestPractices),
		string(scan.Status),
		scan.Progress,
		scan.Stage,
		scan.ErrorMessage,
		scan.TaskProcessID,
		scan.WorkerStatus,
		scan.BrowserID,
		scan.BrowserCDPURL,
		formatStoreTime(scan.CreatedAt),
		nullableStoreTimeValue(scan.StartedAt),
		nullableStoreTimeValue(scan.FinishedAt),
		scan.Summary.Total,
		scan.Summary.Critical,
		scan.Summary.Serious,
		scan.Summary.Moderate,
		scan.AxeRaw,
		scan.Evidence.DesktopImageURL,
		scan.Evidence.TabletImageURL,
		scan.Evidence.MobileImageURL,
		scan.Evidence.RecordingImageURL,
	)
	if err != nil {
		return fmt.Errorf("upsert scan: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM scan_findings WHERE scan_id = ?`, scan.ID); err != nil {
		return fmt.Errorf("delete scan findings: %w", err)
	}

	for index, finding := range scan.Findings {
		tagsJSON := marshalStringJSONArray(finding.Tags)
		targetsJSON := marshalStringJSONArray(finding.Targets)

		_, err := tx.Exec(`
			INSERT INTO scan_findings (
				scan_id,
				finding_id,
				rule_id,
				title,
				description,
				snippet,
				node_html,
				failure_summary,
				severity,
				impact,
				standard,
				criterion,
				method,
				help_url,
				tags_json,
				targets_json,
				raw_json,
				sort_order
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			scan.ID,
			finding.ID,
			finding.RuleID,
			finding.Title,
			finding.Description,
			finding.Snippet,
			finding.NodeHTML,
			finding.Failure,
			string(finding.Severity),
			finding.Impact,
			finding.Standard,
			finding.Criterion,
			string(finding.Method),
			finding.HelpURL,
			tagsJSON,
			targetsJSON,
			finding.RawJSON,
			index,
		)
		if err != nil {
			return fmt.Errorf("insert scan finding: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan transaction: %w", err)
	}

	return nil
}

func defaultEvidence() Evidence {
	return Evidence{
		DesktopImageURL:   "https://placeholder.pics/svg/640x360",
		TabletImageURL:    "https://placeholder.pics/svg/400x550",
		MobileImageURL:    "https://placeholder.pics/svg/300x540",
		RecordingImageURL: "",
	}
}

func normalizeEvidence(evidence Evidence) Evidence {
	defaults := defaultEvidence()

	if strings.TrimSpace(evidence.DesktopImageURL) == "" {
		evidence.DesktopImageURL = defaults.DesktopImageURL
	}
	if strings.TrimSpace(evidence.TabletImageURL) == "" {
		evidence.TabletImageURL = defaults.TabletImageURL
	}
	if strings.TrimSpace(evidence.MobileImageURL) == "" {
		evidence.MobileImageURL = defaults.MobileImageURL
	}

	return evidence
}

func summarizeFindings(findings []Finding) Summary {
	summary := Summary{Total: len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeveritySerious:
			summary.Serious++
		case SeverityModerate:
			summary.Moderate++
		}
	}

	return summary
}

func estimateSecondsRemaining(status ScanStatus, progress int) int {
	switch status {
	case ScanStatusCompleted, ScanStatusFailed, ScanStatusCanceled:
		return 0
	default:
		remaining := (100 - progress) * 2
		if remaining < 5 {
			return 5
		}
		return remaining
	}
}

func isTerminalStatus(status ScanStatus) bool {
	return status == ScanStatusCompleted || status == ScanStatusFailed || status == ScanStatusCanceled
}

func generateToken(prefix string, byteLength int) (string, error) {
	if byteLength <= 0 {
		byteLength = 16
	}
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	if strings.TrimSpace(prefix) == "" {
		return base64.RawURLEncoding.EncodeToString(bytes), nil
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(bytes), nil
}

func formatStoreTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseStoreTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
}

func parseNullableStoreTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil, nil
	}

	parsed, err := parseStoreTime(value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func nullableStoreTimeValue(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatStoreTime(*value)
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func intToBool(value int) bool {
	return value != 0
}

func removeScanID(scanIDs []string, scanID string) []string {
	if len(scanIDs) == 0 {
		return scanIDs
	}

	filtered := make([]string, 0, len(scanIDs))
	for _, id := range scanIDs {
		if id == scanID {
			continue
		}
		filtered = append(filtered, id)
	}

	return filtered
}

func cloneFindings(findings []Finding) []Finding {
	cloned := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		copyFinding := finding
		copyFinding.Tags = slices.Clone(finding.Tags)
		copyFinding.Targets = slices.Clone(finding.Targets)
		cloned = append(cloned, copyFinding)
	}
	return cloned
}

func marshalStringJSONArray(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

func parseStringJSONArray(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return []string{}
	}

	var parsed []string
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return []string{}
	}
	return parsed
}

func (s *Service) ensureScansColumn(ctx context.Context, columnName string, columnDDL string) error {
	return s.ensureTableColumn(ctx, "scans", columnName, columnDDL)
}

func (s *Service) ensureScanFindingsColumn(ctx context.Context, columnName string, columnDDL string) error {
	return s.ensureTableColumn(ctx, "scan_findings", columnName, columnDDL)
}

func (s *Service) ensureRecurringScansColumn(ctx context.Context, columnName string, columnDDL string) error {
	return s.ensureTableColumn(ctx, "recurring_scans", columnName, columnDDL)
}

func (s *Service) ensureTableColumn(ctx context.Context, tableName string, columnName string, columnDDL string) error {
	query := fmt.Sprintf("PRAGMA table_info(%s)", tableName)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("read %s table info: %w", tableName, err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan %s table info row: %w", tableName, err)
		}

		if strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(columnName)) {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate %s table info: %w", tableName, err)
	}

	statement := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", tableName, columnName, columnDDL)
	if _, err := s.db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("add %s column %s: %w", tableName, columnName, err)
	}

	return nil
}
