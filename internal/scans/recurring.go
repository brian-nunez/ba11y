package scans

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/brian-nunez/ba11y/internal/auth"
	"github.com/brian-nunez/ba11y/internal/authorization"
	btick "github.com/brian-nunez/btick/sdk/go/scheduler"
)

const recurringWebhookSecretHeader = "X-BA11Y-WEBHOOK-SECRET"

func (s *Service) CreateRecurringScan(ctx context.Context, actor auth.User, input CreateRecurringScanInput) (RecurringScan, error) {
	if input.OwnerUserID == "" {
		input.OwnerUserID = actor.ID
	}
	if input.OwnerEmail == "" {
		input.OwnerEmail = actor.Email
	}
	if input.Type == "" {
		return RecurringScan{}, ErrInvalidScanType
	}
	if strings.TrimSpace(input.Target) == "" {
		return RecurringScan{}, ErrInvalidTarget
	}

	resource := authorization.ScanResource{OwnerUserID: input.OwnerUserID}
	if !s.authorizer.Can(actor, resource, "scans.create") {
		return RecurringScan{}, ErrForbidden
	}

	if err := s.requireBTickWriteConfig(true); err != nil {
		return RecurringScan{}, err
	}

	schedule, err := normalizeRecurringSchedule(input)
	if err != nil {
		return RecurringScan{}, err
	}

	now := s.now().UTC()
	recurringID, err := generateToken("rscan", 12)
	if err != nil {
		return RecurringScan{}, fmt.Errorf("generate recurring scan id: %w", err)
	}

	standard := strings.TrimSpace(input.Standard)
	if standard == "" {
		standard = "WCAG 2.1 Level AA"
	}

	recurring := &RecurringScan{
		ID:                   recurringID,
		SourceScanID:         strings.TrimSpace(input.SourceScanID),
		OwnerUserID:          input.OwnerUserID,
		RequestedByEmail:     input.OwnerEmail,
		Type:                 input.Type,
		Target:               strings.TrimSpace(input.Target),
		Standard:             standard,
		IncludeBestPractices: input.IncludeBestPractices,
		Frequency:            schedule.Frequency,
		CronExpression:       schedule.CronExpression,
		Timezone:             schedule.Timezone,
		Minute:               schedule.Minute,
		HourOfDay:            schedule.HourOfDay,
		DayOfWeek:            schedule.DayOfWeek,
		DayOfMonth:           schedule.DayOfMonth,
		State:                RecurringScanStateEnabled,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}
	if s.btickWebhookSecret != "" {
		headers[recurringWebhookSecretHeader] = s.btickWebhookSecret
	}

	job, err := s.btick.CreateJob(ctx, btick.CreateJobRequest{
		Name:           fmt.Sprintf("ba11y recurring scan %s", recurring.ID),
		Method:         "POST",
		URL:            s.btickWebhookURL,
		Headers:        headers,
		Body:           recurringJobBody(*recurring),
		CronExpression: recurring.CronExpression,
		Timezone:       recurring.Timezone,
		RetryMax:       1,
		TimeoutSeconds: 60,
		Enabled:        true,
	})
	if err != nil {
		return RecurringScan{}, fmt.Errorf("create btick job: %w", err)
	}

	recurring.BTickJobID = strings.TrimSpace(job.ID)
	if recurring.BTickJobID == "" {
		return RecurringScan{}, fmt.Errorf("create btick job: missing job id in response")
	}

	s.mu.Lock()
	s.recurringByID[recurring.ID] = recurring
	s.orderedRecurringIDs = append([]string{recurring.ID}, s.orderedRecurringIDs...)
	if err := s.persistRecurringScanLocked(recurring); err != nil {
		delete(s.recurringByID, recurring.ID)
		s.orderedRecurringIDs = removeScanID(s.orderedRecurringIDs, recurring.ID)
		s.mu.Unlock()
		_ = s.btick.DeleteJob(context.Background(), recurring.BTickJobID)
		return RecurringScan{}, fmt.Errorf("persist recurring scan: %w", err)
	}
	out := s.cloneRecurringScan(recurring)
	s.mu.Unlock()

	return out, nil
}

func (s *Service) ListRecurringScansForUser(_ context.Context, actor auth.User) ([]RecurringScan, error) {
	if !s.authorizer.Can(actor, authorization.ScanResource{OwnerUserID: actor.ID}, "scans.list") {
		return nil, ErrForbidden
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]RecurringScan, 0)
	for _, recurringID := range s.orderedRecurringIDs {
		recurring := s.recurringByID[recurringID]
		if recurring == nil {
			continue
		}
		if actor.IsAdmin() || recurring.OwnerUserID == actor.ID {
			out = append(out, s.cloneRecurringScan(recurring))
		}
	}

	return out, nil
}

func (s *Service) ListRecurringScansForScan(ctx context.Context, actor auth.User, scanID string) ([]RecurringScan, error) {
	scan, err := s.GetScanForUser(ctx, actor, scanID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]RecurringScan, 0)
	for _, recurringID := range s.orderedRecurringIDs {
		recurring := s.recurringByID[recurringID]
		if recurring == nil {
			continue
		}
		if recurring.SourceScanID != scan.ID {
			continue
		}
		if actor.IsAdmin() || recurring.OwnerUserID == actor.ID {
			out = append(out, s.cloneRecurringScan(recurring))
		}
	}

	return out, nil
}

func (s *Service) GetRecurringScanForUser(_ context.Context, actor auth.User, recurringScanID string) (RecurringScan, error) {
	s.mu.RLock()
	recurring := s.recurringByID[strings.TrimSpace(recurringScanID)]
	s.mu.RUnlock()

	if recurring == nil {
		return RecurringScan{}, ErrRecurringScanNotFound
	}

	resource := authorization.ScanResource{OwnerUserID: recurring.OwnerUserID}
	if !s.authorizer.Can(actor, resource, "scans.read") {
		return RecurringScan{}, ErrForbidden
	}

	return s.cloneRecurringScan(recurring), nil
}

func (s *Service) EnableRecurringScan(ctx context.Context, actor auth.User, recurringScanID string) (RecurringScan, error) {
	return s.changeRecurringState(ctx, actor, recurringScanID, RecurringScanStateEnabled)
}

func (s *Service) DisableRecurringScan(ctx context.Context, actor auth.User, recurringScanID string) (RecurringScan, error) {
	return s.changeRecurringState(ctx, actor, recurringScanID, RecurringScanStateDisabled)
}

func (s *Service) StopRecurringScan(ctx context.Context, actor auth.User, recurringScanID string) (RecurringScan, error) {
	return s.changeRecurringState(ctx, actor, recurringScanID, RecurringScanStateStopped)
}

func (s *Service) DeleteRecurringScan(_ context.Context, actor auth.User, recurringScanID string) error {
	s.mu.RLock()
	current := s.recurringByID[recurringScanID]
	if current == nil {
		s.mu.RUnlock()
		return ErrRecurringScanNotFound
	}
	recurring := s.cloneRecurringScan(current)
	s.mu.RUnlock()

	resource := authorization.ScanResource{OwnerUserID: recurring.OwnerUserID}
	if !s.authorizer.Can(actor, resource, "scans.cancel") {
		return ErrForbidden
	}
	if recurring.State != RecurringScanStateStopped {
		return fmt.Errorf("%w: only stopped recurring scans can be deleted", ErrInvalidRecurringSchedule)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored := s.recurringByID[recurringScanID]
	if stored == nil {
		return ErrRecurringScanNotFound
	}
	if stored.State != RecurringScanStateStopped {
		return fmt.Errorf("%w: only stopped recurring scans can be deleted", ErrInvalidRecurringSchedule)
	}

	if _, err := s.db.Exec(`DELETE FROM recurring_scans WHERE id = ?`, recurringScanID); err != nil {
		return fmt.Errorf("delete recurring scan: %w", err)
	}

	delete(s.recurringByID, recurringScanID)
	s.orderedRecurringIDs = removeScanID(s.orderedRecurringIDs, recurringScanID)

	return nil
}

func (s *Service) UpdateRecurringScan(ctx context.Context, actor auth.User, recurringScanID string, input UpdateRecurringScanInput) (RecurringScan, error) {
	s.mu.RLock()
	current := s.recurringByID[recurringScanID]
	if current == nil {
		s.mu.RUnlock()
		return RecurringScan{}, ErrRecurringScanNotFound
	}
	recurring := s.cloneRecurringScan(current)
	s.mu.RUnlock()

	resource := authorization.ScanResource{OwnerUserID: recurring.OwnerUserID}
	if !s.authorizer.Can(actor, resource, "scans.cancel") {
		return RecurringScan{}, ErrForbidden
	}
	if recurring.State == RecurringScanStateStopped {
		return RecurringScan{}, fmt.Errorf("%w: recurring scan has been stopped", ErrInvalidRecurringSchedule)
	}
	if err := s.requireBTickWriteConfig(false); err != nil {
		return RecurringScan{}, err
	}

	schedule, err := normalizeRecurringSchedule(CreateRecurringScanInput{
		Frequency:  input.Frequency,
		Timezone:   input.Timezone,
		Minute:     input.Minute,
		HourOfDay:  input.HourOfDay,
		DayOfWeek:  input.DayOfWeek,
		DayOfMonth: input.DayOfMonth,
	})
	if err != nil {
		return RecurringScan{}, err
	}

	standard := strings.TrimSpace(input.Standard)
	if standard == "" {
		standard = recurring.Standard
	}

	enabled := recurring.State == RecurringScanStateEnabled

	updateRequest := btick.UpdateJobRequest{
		Body:           recurringJobBody(RecurringScan{ID: recurring.ID, OwnerUserID: recurring.OwnerUserID, RequestedByEmail: recurring.RequestedByEmail, Target: recurring.Target, Type: recurring.Type, Standard: standard, IncludeBestPractices: input.IncludeBestPractices}),
		CronExpression: &schedule.CronExpression,
		Timezone:       &schedule.Timezone,
		Enabled:        &enabled,
	}
	if strings.TrimSpace(s.btickWebhookURL) != "" {
		jobName := fmt.Sprintf("ba11y recurring scan %s", recurring.ID)
		method := "POST"
		webhookURL := s.btickWebhookURL
		headers := map[string]string{
			"Content-Type": "application/json",
		}
		if s.btickWebhookSecret != "" {
			headers[recurringWebhookSecretHeader] = s.btickWebhookSecret
		}
		updateRequest.Name = &jobName
		updateRequest.Method = &method
		updateRequest.URL = &webhookURL
		updateRequest.Headers = &headers
	}

	_, err = s.btick.UpdateJob(ctx, recurring.BTickJobID, updateRequest)
	if err != nil {
		return RecurringScan{}, fmt.Errorf("update btick job: %w", err)
	}

	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	stored := s.recurringByID[recurringScanID]
	if stored == nil {
		return RecurringScan{}, ErrRecurringScanNotFound
	}

	stored.Standard = standard
	stored.IncludeBestPractices = input.IncludeBestPractices
	stored.Frequency = schedule.Frequency
	stored.CronExpression = schedule.CronExpression
	stored.Timezone = schedule.Timezone
	stored.Minute = schedule.Minute
	stored.HourOfDay = schedule.HourOfDay
	stored.DayOfWeek = schedule.DayOfWeek
	stored.DayOfMonth = schedule.DayOfMonth
	stored.UpdatedAt = now

	if err := s.persistRecurringScanLocked(stored); err != nil {
		return RecurringScan{}, fmt.Errorf("persist recurring update: %w", err)
	}

	return s.cloneRecurringScan(stored), nil
}

func (s *Service) ListRecurringTriggeredScansForScan(ctx context.Context, actor auth.User, scanID string) ([]Scan, error) {
	scan, err := s.GetScanForUser(ctx, actor, scanID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	recurringIDs := make(map[string]struct{})
	for _, recurringID := range s.orderedRecurringIDs {
		recurring := s.recurringByID[recurringID]
		if recurring == nil {
			continue
		}
		if recurring.SourceScanID != scan.ID {
			continue
		}
		if actor.IsAdmin() || recurring.OwnerUserID == actor.ID {
			recurringIDs[recurring.ID] = struct{}{}
		}
	}

	out := make([]Scan, 0)
	for _, scanID := range s.orderedScanIDs {
		candidate := s.scansByID[scanID]
		if candidate == nil {
			continue
		}
		if _, ok := recurringIDs[candidate.RecurringScanID]; !ok {
			continue
		}
		if actor.IsAdmin() || candidate.OwnerUserID == actor.ID {
			out = append(out, s.cloneScan(candidate))
		}
	}

	return out, nil
}

func (s *Service) TriggerRecurringScanFromWebhook(ctx context.Context, payload RecurringWebhookPayload, providedSecret string) (Scan, error) {
	recurringID := strings.TrimSpace(payload.RecurringScanID)
	if recurringID == "" {
		return Scan{}, fmt.Errorf("%w: recurring_scan_id is required", ErrInvalidRecurringSchedule)
	}

	if expected := strings.TrimSpace(s.btickWebhookSecret); expected != "" {
		secret := strings.TrimSpace(providedSecret)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(secret)) != 1 {
			return Scan{}, ErrInvalidWebhookSecret
		}
	}

	s.mu.RLock()
	recurring := s.recurringByID[recurringID]
	if recurring == nil {
		s.mu.RUnlock()
		return Scan{}, ErrRecurringScanNotFound
	}
	recurringCopy := s.cloneRecurringScan(recurring)
	s.mu.RUnlock()

	if recurringCopy.State != RecurringScanStateEnabled {
		return Scan{}, ErrRecurringScanInactive
	}

	actor := auth.User{
		ID:    recurringCopy.OwnerUserID,
		Email: recurringCopy.RequestedByEmail,
		Roles: []string{"user"},
	}
	createdScan, err := s.CreateScan(ctx, actor, CreateScanInput{
		OwnerUserID:          recurringCopy.OwnerUserID,
		OwnerEmail:           recurringCopy.RequestedByEmail,
		RecurringScanID:      recurringCopy.ID,
		Type:                 recurringCopy.Type,
		Target:               recurringCopy.Target,
		Standard:             recurringCopy.Standard,
		DeviceEmulation:      "Desktop",
		IncludeBestPractices: recurringCopy.IncludeBestPractices,
	})
	if err != nil {
		return Scan{}, err
	}

	triggeredAt := s.now().UTC()
	s.mu.Lock()
	current := s.recurringByID[recurringID]
	if current != nil {
		current.LastTriggeredAt = &triggeredAt
		current.UpdatedAt = triggeredAt
		_ = s.persistRecurringScanLocked(current)
	}
	s.mu.Unlock()

	return createdScan, nil
}

func recurringJobBody(recurring RecurringScan) map[string]any {
	return map[string]any{
		"recurring_scan_id":      recurring.ID,
		"owner_user_id":          recurring.OwnerUserID,
		"owner_email":            recurring.RequestedByEmail,
		"target":                 recurring.Target,
		"scan_type":              recurring.Type,
		"standard":               recurring.Standard,
		"include_best_practices": recurring.IncludeBestPractices,
	}
}

func (s *Service) loadRecurringScans(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			id,
			source_scan_id,
			owner_user_id,
			requested_by_email,
			type,
			target,
			standard,
			include_best_practices,
			frequency,
			cron_expression,
			timezone,
			minute,
			hour_of_day,
			day_of_week,
			day_of_month,
			btick_job_id,
			state,
			last_triggered_at,
			created_at,
			updated_at,
			stopped_at
		FROM recurring_scans
		ORDER BY created_at DESC
	`)
	if err != nil {
		return fmt.Errorf("query recurring scans: %w", err)
	}
	defer rows.Close()

	s.recurringByID = make(map[string]*RecurringScan)
	s.orderedRecurringIDs = make([]string, 0)

	for rows.Next() {
		var (
			includeBestPractices int
			typeRaw              string
			frequencyRaw         string
			stateRaw             string
			lastTriggeredAt      sql.NullString
			createdAtRaw         string
			updatedAtRaw         string
			stoppedAtRaw         sql.NullString
			recurring            RecurringScan
		)

		if err := rows.Scan(
			&recurring.ID,
			&recurring.SourceScanID,
			&recurring.OwnerUserID,
			&recurring.RequestedByEmail,
			&typeRaw,
			&recurring.Target,
			&recurring.Standard,
			&includeBestPractices,
			&frequencyRaw,
			&recurring.CronExpression,
			&recurring.Timezone,
			&recurring.Minute,
			&recurring.HourOfDay,
			&recurring.DayOfWeek,
			&recurring.DayOfMonth,
			&recurring.BTickJobID,
			&stateRaw,
			&lastTriggeredAt,
			&createdAtRaw,
			&updatedAtRaw,
			&stoppedAtRaw,
		); err != nil {
			return fmt.Errorf("scan recurring row: %w", err)
		}

		if parsedType, err := ParseScanType(typeRaw); err == nil {
			recurring.Type = parsedType
		} else {
			recurring.Type = ScanTypeWebPage
		}
		if parsedFrequency, err := ParseRecurringFrequency(frequencyRaw); err == nil {
			recurring.Frequency = parsedFrequency
		} else {
			recurring.Frequency = RecurringFrequencyDaily
		}
		recurring.State = parseRecurringScanState(stateRaw)
		recurring.IncludeBestPractices = intToBool(includeBestPractices)

		recurring.CreatedAt, err = parseStoreTime(createdAtRaw)
		if err != nil {
			return fmt.Errorf("parse recurring created_at: %w", err)
		}
		recurring.UpdatedAt, err = parseStoreTime(updatedAtRaw)
		if err != nil {
			return fmt.Errorf("parse recurring updated_at: %w", err)
		}
		recurring.LastTriggeredAt, err = parseNullableStoreTime(lastTriggeredAt)
		if err != nil {
			return fmt.Errorf("parse recurring last_triggered_at: %w", err)
		}
		recurring.StoppedAt, err = parseNullableStoreTime(stoppedAtRaw)
		if err != nil {
			return fmt.Errorf("parse recurring stopped_at: %w", err)
		}

		recurringCopy := recurring
		s.recurringByID[recurring.ID] = &recurringCopy
		s.orderedRecurringIDs = append(s.orderedRecurringIDs, recurring.ID)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate recurring rows: %w", err)
	}

	return nil
}

func (s *Service) persistRecurringScanLocked(recurring *RecurringScan) error {
	if recurring == nil {
		return nil
	}

	_, err := s.db.Exec(`
		INSERT INTO recurring_scans (
			id,
			source_scan_id,
			owner_user_id,
			requested_by_email,
			type,
			target,
			standard,
			include_best_practices,
			frequency,
			cron_expression,
			timezone,
			minute,
			hour_of_day,
			day_of_week,
			day_of_month,
			btick_job_id,
			state,
			last_triggered_at,
			created_at,
			updated_at,
			stopped_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			source_scan_id = excluded.source_scan_id,
			owner_user_id = excluded.owner_user_id,
			requested_by_email = excluded.requested_by_email,
			type = excluded.type,
			target = excluded.target,
			standard = excluded.standard,
			include_best_practices = excluded.include_best_practices,
			frequency = excluded.frequency,
			cron_expression = excluded.cron_expression,
			timezone = excluded.timezone,
			minute = excluded.minute,
			hour_of_day = excluded.hour_of_day,
			day_of_week = excluded.day_of_week,
			day_of_month = excluded.day_of_month,
			btick_job_id = excluded.btick_job_id,
			state = excluded.state,
			last_triggered_at = excluded.last_triggered_at,
			created_at = excluded.created_at,
			updated_at = excluded.updated_at,
			stopped_at = excluded.stopped_at
	`,
		recurring.ID,
		recurring.SourceScanID,
		recurring.OwnerUserID,
		recurring.RequestedByEmail,
		string(recurring.Type),
		recurring.Target,
		recurring.Standard,
		boolToInt(recurring.IncludeBestPractices),
		string(recurring.Frequency),
		recurring.CronExpression,
		recurring.Timezone,
		recurring.Minute,
		recurring.HourOfDay,
		recurring.DayOfWeek,
		recurring.DayOfMonth,
		recurring.BTickJobID,
		string(recurring.State),
		nullableStoreTimeValue(recurring.LastTriggeredAt),
		formatStoreTime(recurring.CreatedAt),
		formatStoreTime(recurring.UpdatedAt),
		nullableStoreTimeValue(recurring.StoppedAt),
	)
	if err != nil {
		return fmt.Errorf("upsert recurring scan: %w", err)
	}

	return nil
}

func (s *Service) changeRecurringState(ctx context.Context, actor auth.User, recurringScanID string, desiredState RecurringScanState) (RecurringScan, error) {
	s.mu.RLock()
	current := s.recurringByID[recurringScanID]
	if current == nil {
		s.mu.RUnlock()
		return RecurringScan{}, ErrRecurringScanNotFound
	}
	recurring := s.cloneRecurringScan(current)
	s.mu.RUnlock()

	resource := authorization.ScanResource{OwnerUserID: recurring.OwnerUserID}
	if !s.authorizer.Can(actor, resource, "scans.cancel") {
		return RecurringScan{}, ErrForbidden
	}

	if recurring.State == RecurringScanStateStopped && desiredState != RecurringScanStateStopped {
		return RecurringScan{}, fmt.Errorf("%w: recurring scan has been stopped", ErrInvalidRecurringSchedule)
	}
	if recurring.State == desiredState {
		return recurring, nil
	}

	if err := s.requireBTickWriteConfig(false); err != nil {
		return RecurringScan{}, err
	}

	switch desiredState {
	case RecurringScanStateEnabled:
		if _, err := s.btick.ResumeJob(ctx, recurring.BTickJobID); err != nil {
			return RecurringScan{}, fmt.Errorf("resume btick job: %w", err)
		}
	case RecurringScanStateDisabled:
		if _, err := s.btick.PauseJob(ctx, recurring.BTickJobID); err != nil {
			return RecurringScan{}, fmt.Errorf("pause btick job: %w", err)
		}
	case RecurringScanStateStopped:
		err := s.btick.DeleteJob(ctx, recurring.BTickJobID)
		if err != nil && !isBTickNotFound(err) {
			return RecurringScan{}, fmt.Errorf("delete btick job: %w", err)
		}
	default:
		return RecurringScan{}, fmt.Errorf("%w: unsupported state transition", ErrInvalidRecurringSchedule)
	}

	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	stored := s.recurringByID[recurringScanID]
	if stored == nil {
		return RecurringScan{}, ErrRecurringScanNotFound
	}

	stored.State = desiredState
	stored.UpdatedAt = now
	if desiredState == RecurringScanStateStopped {
		stored.StoppedAt = &now
	} else {
		stored.StoppedAt = nil
	}

	if err := s.persistRecurringScanLocked(stored); err != nil {
		return RecurringScan{}, fmt.Errorf("persist recurring state change: %w", err)
	}

	return s.cloneRecurringScan(stored), nil
}

func (s *Service) cloneRecurringScan(recurring *RecurringScan) RecurringScan {
	if recurring == nil {
		return RecurringScan{}
	}

	copyRecurring := *recurring
	if recurring.LastTriggeredAt != nil {
		lastTriggeredAt := *recurring.LastTriggeredAt
		copyRecurring.LastTriggeredAt = &lastTriggeredAt
	}
	if recurring.StoppedAt != nil {
		stoppedAt := *recurring.StoppedAt
		copyRecurring.StoppedAt = &stoppedAt
	}
	return copyRecurring
}

func (s *Service) requireBTickWriteConfig(requireWebhookURL bool) error {
	if s.btick == nil || !s.btickAPIKeyAvailable {
		return fmt.Errorf("%w: set BTICK_BASE_URL and BTICK_API_KEY", ErrRecurringFeatureDisabled)
	}
	if requireWebhookURL && strings.TrimSpace(s.btickWebhookURL) == "" {
		return fmt.Errorf("%w: set BTICK_WEBHOOK_URL", ErrRecurringFeatureDisabled)
	}
	return nil
}

type normalizedRecurringSchedule struct {
	Frequency      RecurringFrequency
	CronExpression string
	Timezone       string
	Minute         int
	HourOfDay      int
	DayOfWeek      int
	DayOfMonth     int
}

func normalizeRecurringSchedule(input CreateRecurringScanInput) (normalizedRecurringSchedule, error) {
	frequency := input.Frequency
	if frequency == "" {
		return normalizedRecurringSchedule{}, fmt.Errorf("%w: frequency is required", ErrInvalidRecurringSchedule)
	}
	switch frequency {
	case RecurringFrequencyHourly, RecurringFrequencyDaily, RecurringFrequencyWeekly, RecurringFrequencyMonthly:
	default:
		return normalizedRecurringSchedule{}, fmt.Errorf("%w: unsupported frequency", ErrInvalidRecurringSchedule)
	}

	timezone := strings.TrimSpace(input.Timezone)
	if timezone == "" {
		timezone = "UTC"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return normalizedRecurringSchedule{}, fmt.Errorf("%w: invalid timezone", ErrInvalidRecurringSchedule)
	}

	minute := input.Minute
	if minute < 0 || minute > 59 {
		return normalizedRecurringSchedule{}, fmt.Errorf("%w: minute must be between 0 and 59", ErrInvalidRecurringSchedule)
	}

	hourOfDay := input.HourOfDay
	dayOfWeek := input.DayOfWeek
	dayOfMonth := input.DayOfMonth
	cronExpression := ""

	switch frequency {
	case RecurringFrequencyHourly:
		cronExpression = fmt.Sprintf("%d * * * *", minute)
		hourOfDay = 0
		dayOfWeek = 0
		dayOfMonth = 1
	case RecurringFrequencyDaily:
		if hourOfDay < 0 || hourOfDay > 23 {
			return normalizedRecurringSchedule{}, fmt.Errorf("%w: hour must be between 0 and 23", ErrInvalidRecurringSchedule)
		}
		cronExpression = fmt.Sprintf("%d %d * * *", minute, hourOfDay)
		dayOfWeek = 0
		dayOfMonth = 1
	case RecurringFrequencyWeekly:
		if hourOfDay < 0 || hourOfDay > 23 {
			return normalizedRecurringSchedule{}, fmt.Errorf("%w: hour must be between 0 and 23", ErrInvalidRecurringSchedule)
		}
		if dayOfWeek < 0 || dayOfWeek > 6 {
			return normalizedRecurringSchedule{}, fmt.Errorf("%w: weekday must be between 0 and 6", ErrInvalidRecurringSchedule)
		}
		cronExpression = fmt.Sprintf("%d %d * * %d", minute, hourOfDay, dayOfWeek)
		dayOfMonth = 1
	case RecurringFrequencyMonthly:
		if hourOfDay < 0 || hourOfDay > 23 {
			return normalizedRecurringSchedule{}, fmt.Errorf("%w: hour must be between 0 and 23", ErrInvalidRecurringSchedule)
		}
		if dayOfMonth < 1 || dayOfMonth > 31 {
			return normalizedRecurringSchedule{}, fmt.Errorf("%w: day of month must be between 1 and 31", ErrInvalidRecurringSchedule)
		}
		cronExpression = fmt.Sprintf("%d %d %d * *", minute, hourOfDay, dayOfMonth)
		dayOfWeek = 0
	}

	return normalizedRecurringSchedule{
		Frequency:      frequency,
		CronExpression: cronExpression,
		Timezone:       timezone,
		Minute:         minute,
		HourOfDay:      hourOfDay,
		DayOfWeek:      dayOfWeek,
		DayOfMonth:     dayOfMonth,
	}, nil
}

func parseRecurringScanState(raw string) RecurringScanState {
	state := RecurringScanState(strings.ToLower(strings.TrimSpace(raw)))
	switch state {
	case RecurringScanStateEnabled, RecurringScanStateDisabled, RecurringScanStateStopped:
		return state
	default:
		return RecurringScanStateEnabled
	}
}

func isBTickNotFound(err error) bool {
	var apiErr *btick.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
		return true
	}
	return false
}
