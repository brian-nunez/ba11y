package pages

import (
	"fmt"
	"strings"
	"time"

	"github.com/brian-nunez/ba11y/internal/scans"
)

type SessionView struct {
	Authenticated bool
	Email         string
}

type ScanFormView struct {
	SelectedType         string
	Target               string
	Standard             string
	IncludeBestPractices bool
}

type RecurringFormView struct {
	SelectedType         string
	Target               string
	Standard             string
	IncludeBestPractices bool
	Frequency            string
	Minute               int
	HourOfDay            int
	DayOfWeek            int
	DayOfMonth           int
	Timezone             string
}

func DefaultScanForm() ScanFormView {
	return ScanFormView{
		SelectedType:         string(scans.ScanTypeWebPage),
		Standard:             "WCAG 2.1 Level AA",
		IncludeBestPractices: false,
	}
}

func DefaultRecurringForm() RecurringFormView {
	return RecurringFormView{
		SelectedType:         string(scans.ScanTypeWebPage),
		Standard:             "WCAG 2.1 Level AA",
		IncludeBestPractices: false,
		Frequency:            string(scans.RecurringFrequencyDaily),
		Minute:               0,
		HourOfDay:            9,
		DayOfWeek:            1,
		DayOfMonth:           1,
		Timezone:             "UTC",
	}
}

func (f ScanFormView) IsSelected(scanType scans.ScanType) bool {
	return strings.EqualFold(f.SelectedType, string(scanType))
}

func StandardOptions() []string {
	return []string{
		"WCAG 2.0 Level A",
		"WCAG 2.0 Level AA",
		"WCAG 2.0 Level AAA",
		"WCAG 2.1 Level A",
		"WCAG 2.1 Level AA",
		"WCAG 2.2 Level AA",
	}
}

func HumanScanType(scanType scans.ScanType) string {
	switch scanType {
	case scans.ScanTypeWebPage:
		return "Web Page"
	case scans.ScanTypeEmail:
		return "Email"
	default:
		return strings.Title(string(scanType))
	}
}

func SeverityBadgeClass(severity scans.FindingSeverity) string {
	switch severity {
	case scans.SeverityCritical:
		return "bg-red-100 text-red-600"
	case scans.SeveritySerious:
		return "bg-orange-100 text-orange-600"
	default:
		return "bg-slate-200 text-slate-600"
	}
}

func SeverityLabel(severity scans.FindingSeverity) string {
	switch severity {
	case scans.SeverityCritical:
		return "Critical"
	case scans.SeveritySerious:
		return "Serious"
	case scans.SeverityModerate:
		return "Moderate"
	default:
		return strings.Title(string(severity))
	}
}

func MethodLabel(method scans.FindingMethod) string {
	switch method {
	case scans.MethodAutomated:
		return "Automated"
	case scans.MethodManual:
		return "Manual Review"
	default:
		return strings.Title(string(method))
	}
}

func FormattedScanTime(createdAt time.Time) string {
	if createdAt.IsZero() {
		return ""
	}
	return createdAt.UTC().Format("Jan 2, 2006, 15:04 UTC")
}

func FormattedOptionalScanTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return "Never"
	}
	return FormattedScanTime(*value)
}

func RiskLabel(summary scans.Summary) string {
	if summary.Critical >= 3 {
		return "High Risk"
	}
	if summary.Critical >= 1 || summary.Serious >= 8 {
		return "Medium Risk"
	}
	return "Low Risk"
}

func RiskClass(summary scans.Summary) string {
	if summary.Critical >= 3 {
		return "bg-red-100 text-red-600"
	}
	if summary.Critical >= 1 || summary.Serious >= 8 {
		return "bg-orange-100 text-orange-600"
	}
	return "bg-emerald-100 text-emerald-600"
}

func ScanProgressLabel(scan scans.Scan) string {
	if scan.Status == scans.ScanStatusFailed {
		return "Failed"
	}
	if scan.Status == scans.ScanStatusCompleted {
		return "Complete"
	}
	return fmt.Sprintf("%d%% Complete", scan.Progress)
}

func ScanTypeCardClass(selected bool) string {
	base := "group relative flex cursor-pointer items-center gap-2 rounded-lg border bg-white px-3 py-2 transition-colors"
	if selected {
		return base + " border-[#137fec] text-[#137fec]"
	}
	return base + " border-slate-200 text-slate-600 hover:border-[#137fec]/40"
}

func ScanTypeIconClass(selected bool) string {
	base := "size-6 rounded-md flex items-center justify-center"
	if selected {
		return base + " bg-[#137fec]/15 text-[#137fec]"
	}
	return base + " bg-slate-100 text-slate-500"
}

func HistoryStatusClass(status scans.ScanStatus) string {
	base := "inline-flex rounded-full px-2.5 py-1 text-xs font-semibold"
	switch status {
	case scans.ScanStatusCompleted:
		return base + " bg-emerald-100 text-emerald-700"
	case scans.ScanStatusFailed:
		return base + " bg-red-100 text-red-700"
	case scans.ScanStatusRunning, scans.ScanStatusPending:
		return base + " bg-sky-100 text-sky-700"
	case scans.ScanStatusCanceled:
		return base + " bg-slate-200 text-slate-700"
	default:
		return base + " bg-slate-200 text-slate-700"
	}
}

func HasRecordingEvidence(scan scans.Scan) bool {
	recordingURL := strings.TrimSpace(scan.Evidence.RecordingImageURL)
	if recordingURL == "" {
		return false
	}
	// Placeholder image should not be treated as a true recording.
	if strings.Contains(recordingURL, "placeholder.pics/svg") {
		return false
	}
	return true
}

func RecurringStateClass(state scans.RecurringScanState) string {
	base := "inline-flex rounded-full px-2.5 py-1 text-xs font-semibold"
	switch state {
	case scans.RecurringScanStateEnabled:
		return base + " bg-emerald-100 text-emerald-700"
	case scans.RecurringScanStateDisabled:
		return base + " bg-amber-100 text-amber-700"
	case scans.RecurringScanStateStopped:
		return base + " bg-slate-200 text-slate-700"
	default:
		return base + " bg-slate-200 text-slate-700"
	}
}

func RecurringStateLabel(state scans.RecurringScanState) string {
	switch state {
	case scans.RecurringScanStateEnabled:
		return "Enabled"
	case scans.RecurringScanStateDisabled:
		return "Disabled"
	case scans.RecurringScanStateStopped:
		return "Stopped"
	default:
		return strings.Title(string(state))
	}
}

func RecurringFrequencyLabel(frequency scans.RecurringFrequency) string {
	switch frequency {
	case scans.RecurringFrequencyHourly:
		return "Hourly"
	case scans.RecurringFrequencyDaily:
		return "Daily"
	case scans.RecurringFrequencyWeekly:
		return "Weekly"
	case scans.RecurringFrequencyMonthly:
		return "Monthly"
	default:
		return strings.Title(string(frequency))
	}
}

func WeekdayLabel(day int) string {
	labels := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	if day < 0 || day >= len(labels) {
		return "Unknown"
	}
	return labels[day]
}

func RecurringScheduleLabel(recurring scans.RecurringScan) string {
	switch recurring.Frequency {
	case scans.RecurringFrequencyHourly:
		return fmt.Sprintf("Every hour at minute %02d", recurring.Minute)
	case scans.RecurringFrequencyDaily:
		return fmt.Sprintf("Daily at %02d:%02d", recurring.HourOfDay, recurring.Minute)
	case scans.RecurringFrequencyWeekly:
		return fmt.Sprintf("Weekly on %s at %02d:%02d", WeekdayLabel(recurring.DayOfWeek), recurring.HourOfDay, recurring.Minute)
	case scans.RecurringFrequencyMonthly:
		return fmt.Sprintf("Monthly on day %d at %02d:%02d", recurring.DayOfMonth, recurring.HourOfDay, recurring.Minute)
	default:
		return recurring.CronExpression
	}
}

func RecurringFormAction(scanID string, editingRecurringID string) string {
	if strings.TrimSpace(editingRecurringID) != "" {
		return "/scans/recurring/" + editingRecurringID + "/update"
	}
	return "/scans/" + scanID + "/recurring"
}
