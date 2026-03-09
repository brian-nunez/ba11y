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
	case ScanTypeWebPage:
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

type RecurringFrequency string

const (
	RecurringFrequencyHourly  RecurringFrequency = "hourly"
	RecurringFrequencyDaily   RecurringFrequency = "daily"
	RecurringFrequencyWeekly  RecurringFrequency = "weekly"
	RecurringFrequencyMonthly RecurringFrequency = "monthly"
)

func ParseRecurringFrequency(raw string) (RecurringFrequency, error) {
	frequency := RecurringFrequency(strings.ToLower(strings.TrimSpace(raw)))
	switch frequency {
	case RecurringFrequencyHourly, RecurringFrequencyDaily, RecurringFrequencyWeekly, RecurringFrequencyMonthly:
		return frequency, nil
	default:
		return "", fmt.Errorf("unsupported recurring frequency: %s", raw)
	}
}

type RecurringScanState string

const (
	RecurringScanStateEnabled  RecurringScanState = "enabled"
	RecurringScanStateDisabled RecurringScanState = "disabled"
	RecurringScanStateStopped  RecurringScanState = "stopped"
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
	RuleID      string
	Title       string
	Description string
	Snippet     string
	NodeHTML    string
	Failure     string
	Severity    FindingSeverity
	Impact      string
	Standard    string
	Criterion   string
	Method      FindingMethod
	HelpURL     string
	Tags        []string
	Targets     []string
	RawJSON     string
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
	RecurringScanID       string
	Type                  ScanType
	Target                string
	Standard              string
	DeviceEmulation       string
	IncludeVisualContrast bool
	IncludeSubPages       bool
	IncludeBestPractices  bool

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
	AxeRaw   string
}

type RecurringScan struct {
	ID                   string
	SourceScanID         string
	OwnerUserID          string
	RequestedByEmail     string
	Type                 ScanType
	Target               string
	Standard             string
	IncludeBestPractices bool

	Frequency      RecurringFrequency
	CronExpression string
	Timezone       string
	Minute         int
	HourOfDay      int
	DayOfWeek      int
	DayOfMonth     int

	BTickJobID      string
	State           RecurringScanState
	LastTriggeredAt *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	StoppedAt       *time.Time
}

type CreateScanInput struct {
	OwnerUserID           string
	OwnerEmail            string
	RecurringScanID       string
	Type                  ScanType
	Target                string
	Standard              string
	DeviceEmulation       string
	IncludeVisualContrast bool
	IncludeSubPages       bool
	IncludeBestPractices  bool
}

type CreateRecurringScanInput struct {
	SourceScanID         string
	OwnerUserID          string
	OwnerEmail           string
	Type                 ScanType
	Target               string
	Standard             string
	IncludeBestPractices bool
	Frequency            RecurringFrequency
	Timezone             string
	Minute               int
	HourOfDay            int
	DayOfWeek            int
	DayOfMonth           int
}

type UpdateRecurringScanInput struct {
	Standard             string
	IncludeBestPractices bool
	Frequency            RecurringFrequency
	Timezone             string
	Minute               int
	HourOfDay            int
	DayOfWeek            int
	DayOfMonth           int
}

type RecurringWebhookPayload struct {
	RecurringScanID string `json:"recurring_scan_id"`
	OwnerUserID     string `json:"owner_user_id,omitempty"`
	OwnerEmail      string `json:"owner_email,omitempty"`
	Target          string `json:"target,omitempty"`
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
