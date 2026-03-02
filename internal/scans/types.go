package scans

import (
	"fmt"
	"strings"
	"time"
)

type ScanType string

const (
	ScanTypeWebPage ScanType = "webpage"
	ScanTypeEmail   ScanType = "email"
)

func ParseScanType(raw string) (ScanType, error) {
	scanType := ScanType(strings.ToLower(strings.TrimSpace(raw)))
	switch scanType {
	case ScanTypeWebPage, ScanTypeEmail:
		return scanType, nil
	default:
		return "", fmt.Errorf("unsupported scan type: %s", raw)
	}
}

type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCanceled  ScanStatus = "canceled"
)

type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeveritySerious  FindingSeverity = "serious"
	SeverityModerate FindingSeverity = "moderate"
)

type FindingMethod string

const (
	MethodAutomated FindingMethod = "automated"
	MethodManual    FindingMethod = "manual"
)

type Finding struct {
	ID          string
	Title       string
	Description string
	Snippet     string
	Severity    FindingSeverity
	Standard    string
	Criterion   string
	Method      FindingMethod
}

type Summary struct {
	Total    int
	Critical int
	Serious  int
	Moderate int
}

type Evidence struct {
	DesktopImageURL   string
	TabletImageURL    string
	MobileImageURL    string
	RecordingImageURL string
}

type Scan struct {
	ID                    string
	OwnerUserID           string
	RequestedByEmail      string
	Type                  ScanType
	Target                string
	Standard              string
	DeviceEmulation       string
	IncludeVisualContrast bool
	IncludeSubPages       bool

	Status       ScanStatus
	Progress     int
	Stage        string
	ErrorMessage string

	TaskProcessID string
	WorkerStatus  string
	BrowserID     string
	BrowserCDPURL string

	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time

	Findings []Finding
	Summary  Summary
	Evidence Evidence
}

type CreateScanInput struct {
	OwnerUserID           string
	OwnerEmail            string
	Type                  ScanType
	Target                string
	Standard              string
	DeviceEmulation       string
	IncludeVisualContrast bool
	IncludeSubPages       bool
}

type StatusPayload struct {
	ID               string     `json:"id"`
	Status           ScanStatus `json:"status"`
	Progress         int        `json:"progress"`
	Stage            string     `json:"stage"`
	ErrorMessage     string     `json:"errorMessage,omitempty"`
	TaskProcessID    string     `json:"taskProcessId"`
	WorkerStatus     string     `json:"workerStatus,omitempty"`
	EstimatedSeconds int        `json:"estimatedSeconds"`
}
