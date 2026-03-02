package scans

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/playwright-community/playwright-go"
)

const axeCoreCDNURL = "https://cdn.jsdelivr.net/npm/axe-core@4.10.3/axe.min.js"

type axeNode struct {
	HTML           string   `json:"html"`
	Target         []string `json:"target"`
	FailureSummary string   `json:"failureSummary"`
}

type axeViolation struct {
	ID          string    `json:"id"`
	Impact      string    `json:"impact"`
	Help        string    `json:"help"`
	Description string    `json:"description"`
	HelpURL     string    `json:"helpUrl"`
	Tags        []string  `json:"tags"`
	Nodes       []axeNode `json:"nodes"`
}

type axeResultPayload struct {
	Violations []axeViolation `json:"violations"`
}

type AxeAuditResult struct {
	Findings []Finding
	RawJSON  string
}

func installPlaywrightDriver() error {
	return playwright.Install(&playwright.RunOptions{SkipInstallBrowsers: true})
}

func runAxeAudit(page playwright.Page, standard string, includeBestPractices bool) (AxeAuditResult, error) {
	if _, err := page.AddScriptTag(playwright.PageAddScriptTagOptions{
		URL: playwright.String(axeCoreCDNURL),
	}); err != nil {
		return AxeAuditResult{}, fmt.Errorf("inject axe-core: %w", err)
	}

	rawResult, err := page.Evaluate(`async (params) => {
		if (typeof axe === "undefined") {
			throw new Error("axe-core not available on page");
		}

		const result = await axe.run(document, {
			runOnly: {
				type: "tag",
				values: params.tags,
			},
		});

		return {
			violations: (result.violations || []).map((v) => ({
				id: v.id,
				impact: v.impact || "moderate",
				help: v.help || v.id,
				description: v.description || "",
				helpUrl: v.helpUrl || "",
				tags: Array.isArray(v.tags) ? v.tags : [],
				nodes: (v.nodes || []).map((n) => ({
					html: n.html || "",
					target: Array.isArray(n.target) ? n.target : [],
					failureSummary: n.failureSummary || "",
				})),
			})),
		};
	}`, map[string]any{
		"tags": standardToAxeTags(standard, includeBestPractices),
	})
	if err != nil {
		return AxeAuditResult{}, fmt.Errorf("run axe-core: %w", err)
	}

	payloadBytes, err := json.Marshal(rawResult)
	if err != nil {
		return AxeAuditResult{}, fmt.Errorf("marshal axe result: %w", err)
	}

	var payload axeResultPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return AxeAuditResult{}, fmt.Errorf("unmarshal axe result: %w", err)
	}

	normalizedPayload, err := json.Marshal(payload)
	if err != nil {
		return AxeAuditResult{}, fmt.Errorf("marshal normalized axe payload: %w", err)
	}

	return AxeAuditResult{
		Findings: mapAxeViolationsToFindings(payload.Violations, standard),
		RawJSON:  string(normalizedPayload),
	}, nil
}

func setViewportForDevice(page playwright.Page, device string) error {
	width, height := viewportDimensions(device)
	return page.SetViewportSize(width, height)
}

func viewportDimensions(device string) (int, int) {
	normalized := strings.ToLower(strings.TrimSpace(device))
	switch {
	case strings.Contains(normalized, "iphone"):
		return 390, 844
	case strings.Contains(normalized, "pixel"):
		return 412, 915
	case strings.Contains(normalized, "ipad"), strings.Contains(normalized, "tablet"):
		return 820, 1180
	default:
		return 1280, 800
	}
}

func loadTarget(page playwright.Page, scan Scan) error {
	target := strings.TrimSpace(scan.Target)
	if target == "" {
		return ErrInvalidTarget
	}

	switch scan.Type {
	case ScanTypeWebPage:
		normalizedURL, err := normalizeScanURL(target)
		if err != nil {
			return err
		}
		if _, err := page.Goto(normalizedURL, playwright.PageGotoOptions{
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
			Timeout:   playwright.Float(60000),
		}); err != nil {
			return fmt.Errorf("navigate to page: %w", err)
		}
	case ScanTypeEmail:
		if looksLikeURL(target) {
			normalizedURL, err := normalizeScanURL(target)
			if err != nil {
				return err
			}
			if _, err := page.Goto(normalizedURL, playwright.PageGotoOptions{
				WaitUntil: playwright.WaitUntilStateDomcontentloaded,
				Timeout:   playwright.Float(60000),
			}); err != nil {
				return fmt.Errorf("navigate to email URL: %w", err)
			}
			break
		}

		htmlContent := target
		if !looksLikeHTML(target) {
			htmlContent = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head><body><pre style=\"white-space:pre-wrap;font-family:Arial,sans-serif\">" + html.EscapeString(target) + "</pre></body></html>"
		}

		if err := page.SetContent(htmlContent, playwright.PageSetContentOptions{
			WaitUntil: playwright.WaitUntilStateLoad,
			Timeout:   playwright.Float(60000),
		}); err != nil {
			return fmt.Errorf("set email content: %w", err)
		}
	default:
		return ErrInvalidScanType
	}

	return nil
}

func captureEvidence(page playwright.Page, _ string) (Evidence, error) {
	type shot struct {
		name   string
		width  int
		height int
	}

	shots := []shot{
		{name: "desktop", width: 1440, height: 900},
		{name: "tablet", width: 768, height: 1024},
		{name: "mobile", width: 390, height: 844},
	}

	urls := make(map[string]string, len(shots))
	for _, shotConfig := range shots {
		if err := page.SetViewportSize(shotConfig.width, shotConfig.height); err != nil {
			return defaultEvidence(), fmt.Errorf("set %s viewport: %w", shotConfig.name, err)
		}

		imageBytes, err := page.Screenshot(playwright.PageScreenshotOptions{
			FullPage: playwright.Bool(true),
		})
		if err != nil {
			return defaultEvidence(), fmt.Errorf("capture %s screenshot: %w", shotConfig.name, err)
		}

		urls[shotConfig.name] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(imageBytes)
	}

	return Evidence{
		DesktopImageURL:   urls["desktop"],
		TabletImageURL:    urls["tablet"],
		MobileImageURL:    urls["mobile"],
		RecordingImageURL: "",
	}, nil
}

func normalizeScanURL(raw string) (string, error) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return "", ErrInvalidTarget
	}

	if !strings.HasPrefix(strings.ToLower(candidate), "http://") && !strings.HasPrefix(strings.ToLower(candidate), "https://") {
		candidate = "https://" + candidate
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid URL: %s", raw)
	}

	return parsed.String(), nil
}

func looksLikeURL(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func looksLikeHTML(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "<html") || strings.Contains(lower, "<body") || strings.Contains(lower, "<!doctype") || (strings.Contains(lower, "<") && strings.Contains(lower, ">"))
}

func standardToAxeTags(standard string, includeBestPractices bool) []string {
	seen := map[string]struct{}{}
	tags := make([]string, 0)
	add := func(values ...string) {
		for _, value := range values {
			tag := strings.TrimSpace(strings.ToLower(value))
			if tag == "" {
				continue
			}
			if _, ok := seen[tag]; ok {
				continue
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}
	}

	switch strings.ToLower(strings.TrimSpace(standard)) {
	case strings.ToLower("WCAG 2.0 Level A"):
		add("wcag2a")
	case strings.ToLower("WCAG 2.0 Level AA"):
		add("wcag2a", "wcag2aa")
	case strings.ToLower("WCAG 2.0 Level AAA"):
		add("wcag2a", "wcag2aa", "wcag2aaa")
	case strings.ToLower("WCAG 2.1 Level A"):
		add("wcag2a", "wcag21a")
	case strings.ToLower("WCAG 2.2 Level AA"):
		add("wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa")
	case strings.ToLower("WCAG 2.1 Level AA"):
		add("wcag2a", "wcag2aa", "wcag21a", "wcag21aa")
	default:
		add("wcag2a", "wcag2aa", "wcag21a", "wcag21aa")
	}

	if includeBestPractices {
		add("best-practice")
	}

	return tags
}

func mapAxeViolationsToFindings(violations []axeViolation, standard string) []Finding {
	findings := make([]Finding, 0)
	for _, violation := range violations {
		nodes := violation.Nodes
		if len(nodes) == 0 {
			nodes = []axeNode{{}}
		}

		for index, node := range nodes {
			title := strings.TrimSpace(violation.Help)
			if title == "" {
				title = strings.TrimSpace(violation.ID)
			}

			description := compactWhitespace(node.FailureSummary)
			if description == "" {
				description = compactWhitespace(violation.Description)
			}

			snippet := compactWhitespace(node.HTML)
			if snippet == "" && len(node.Target) > 0 {
				snippet = strings.Join(node.Target, ", ")
			}

			findingID := fmt.Sprintf("%s-%d", violation.ID, index+1)
			rawFindingJSON, err := json.Marshal(struct {
				Violation axeViolation `json:"violation"`
				Node      axeNode      `json:"node"`
				NodeIndex int          `json:"nodeIndex"`
			}{
				Violation: violation,
				Node:      node,
				NodeIndex: index,
			})
			if err != nil {
				rawFindingJSON = []byte("{}")
			}

			findings = append(findings, Finding{
				ID:          findingID,
				RuleID:      strings.TrimSpace(violation.ID),
				Title:       title,
				Description: description,
				Snippet:     truncate(snippet, 280),
				NodeHTML:    compactWhitespace(node.HTML),
				Failure:     compactWhitespace(node.FailureSummary),
				Severity:    mapAxeImpact(violation.Impact),
				Impact:      strings.ToLower(strings.TrimSpace(violation.Impact)),
				Standard:    standard,
				Criterion:   criterionFromTags(violation.Tags),
				Method:      MethodAutomated,
				HelpURL:     strings.TrimSpace(violation.HelpURL),
				Tags:        cleanStringSlice(violation.Tags),
				Targets:     cleanStringSlice(node.Target),
				RawJSON:     string(rawFindingJSON),
			})
		}
	}

	return findings
}

func mapAxeImpact(impact string) FindingSeverity {
	switch strings.ToLower(strings.TrimSpace(impact)) {
	case "critical":
		return SeverityCritical
	case "serious":
		return SeveritySerious
	default:
		return SeverityModerate
	}
}

var wcagDigitsPattern = regexp.MustCompile(`^wcag([0-9]{3,4})$`)

func criterionFromTags(tags []string) string {
	for _, tag := range tags {
		normalized := strings.ToLower(strings.TrimSpace(tag))
		matches := wcagDigitsPattern.FindStringSubmatch(normalized)
		if len(matches) != 2 {
			continue
		}

		parts := make([]string, 0, len(matches[1]))
		for _, digit := range matches[1] {
			parts = append(parts, string(digit))
		}
		if len(parts) == 0 {
			continue
		}

		return "Success Criterion " + strings.Join(parts, ".")
	}

	return "Axe Rule"
}

func compactWhitespace(value string) string {
	fields := strings.Fields(strings.TrimSpace(value))
	return strings.Join(fields, " ")
}

func truncate(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}

func cleanStringSlice(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
