package scans

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/brian-nunez/ba11y/internal/auth"
	"github.com/brian-nunez/ba11y/internal/authorization"
	"github.com/brian-nunez/bbaas-api/sdk/go/bbaas"
	worker "github.com/brian-nunez/task-orchestration"
)

var (
	ErrForbidden       = errors.New("forbidden")
	ErrScanNotFound    = errors.New("scan not found")
	ErrInvalidTarget   = errors.New("target is required")
	ErrInvalidScanType = errors.New("invalid scan type")
)

type Config struct {
	BBAASBaseURL       string
	BBAASAPIToken      string
	WorkerConcurrency  int
	WorkerLogPath      string
	WorkerDatabasePath string
}

type Service struct {
	mu             sync.RWMutex
	scansByID      map[string]*Scan
	orderedScanIDs []string

	authorizer *authorization.ScanAuthorizer
	bbaas      *bbaas.Client
	apiToken   string
	workerPool *worker.WorkerPool
	now        func() time.Time
}

func NewService(config Config, authorizer *authorization.ScanAuthorizer) (*Service, error) {
	baseURL := strings.TrimSpace(config.BBAASBaseURL)
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8080"
	}

	client, err := bbaas.NewClient(baseURL, bbaas.WithAPIToken(strings.TrimSpace(config.BBAASAPIToken)))
	if err != nil {
		return nil, fmt.Errorf("create bbaas client: %w", err)
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
		databasePath = "./data/tasks.db"
	}

	pool := worker.NewWorkerPool(worker.WorkerPoolConfig{
		Concurrency:  concurrency,
		LogPath:      logPath,
		DatabasePath: databasePath,
	})
	if err := pool.Start(); err != nil {
		return nil, fmt.Errorf("start worker pool: %w", err)
	}

	return &Service{
		scansByID:      make(map[string]*Scan),
		orderedScanIDs: make([]string, 0),
		authorizer:     authorizer,
		bbaas:          client,
		apiToken:       strings.TrimSpace(config.BBAASAPIToken),
		workerPool:     pool,
		now:            time.Now,
	}, nil
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
		device = "Desktop (Chrome)"
	}

	scan := &Scan{
		ID:                    scanID,
		OwnerUserID:           input.OwnerUserID,
		RequestedByEmail:      input.OwnerEmail,
		Type:                  input.Type,
		Target:                strings.TrimSpace(input.Target),
		Standard:              standard,
		DeviceEmulation:       device,
		IncludeVisualContrast: input.IncludeVisualContrast,
		IncludeSubPages:       input.IncludeSubPages,
		Status:                ScanStatusPending,
		Progress:              6,
		Stage:                 "Queued for scanning",
		CreatedAt:             now,
		Evidence:              defaultEvidence(),
	}

	s.mu.Lock()
	s.scansByID[scan.ID] = scan
	s.orderedScanIDs = append([]string{scan.ID}, s.orderedScanIDs...)
	s.mu.Unlock()

	taskInfo, err := s.workerPool.AddTask(&scanTask{service: s, scanID: scan.ID})
	if err != nil {
		s.failScan(scan.ID, "Failed to enqueue scan task")
		return Scan{}, fmt.Errorf("enqueue scan task: %w", err)
	}

	s.mu.Lock()
	scan.TaskProcessID = taskInfo.ProcessID
	scan.WorkerStatus = taskInfo.Status
	s.mu.Unlock()

	return s.cloneScan(scan), nil
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

	if scan.TaskProcessID != "" {
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
}

func (s *Service) setWorkerStatus(scanID string, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	scan := s.scansByID[scanID]
	if scan == nil {
		return
	}
	scan.WorkerStatus = status
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
}

func (s *Service) completeScan(scanID string, findings []Finding) {
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
	scan.FinishedAt = &now
	scan.ErrorMessage = ""
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
	copyScan.Findings = slices.Clone(scan.Findings)
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

func defaultEvidence() Evidence {
	return Evidence{
		DesktopImageURL:   "https://placeholder.pics/svg/640x360",
		TabletImageURL:    "https://placeholder.pics/svg/400x550",
		MobileImageURL:    "https://placeholder.pics/svg/300x540",
		RecordingImageURL: "https://placeholder.pics/svg/640x360",
	}
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
