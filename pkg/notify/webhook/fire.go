package webhook

import (
	"context"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// FireNativeScan loads the native scan row and posts a completion payload.
// No-op when settings/repo are nil or the webhook is not enabled.
func FireNativeScan(settings *config.Settings, repo *database.Repository, scanUUID string) {
	if settings == nil || repo == nil || scanUUID == "" {
		return
	}
	if !settings.Notify.IsWebhookActive() {
		return
	}
	sender := NewSender(settings.Notify.Webhook)
	if sender == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scan, err := repo.GetScanByUUID(ctx, scanUUID)
	if err != nil || scan == nil {
		zap.L().Debug("[Notify] webhook: native scan not found", zap.String("scan_uuid", scanUUID), zap.Error(err))
		return
	}

	status := scan.Status
	if status == "" {
		status = "completed"
	}
	finishedAt := scan.FinishedAt
	if finishedAt.IsZero() {
		finishedAt = time.Now()
	}

	payload := ScanCompletedPayload{
		Event:       "scan.completed",
		ProjectUUID: scan.ProjectUUID,
		ScanUUID:    scan.UUID,
		ScanType:    "native",
		Target:      scan.Target,
		Status:      status,
		StartedAt:   scan.StartedAt,
		FinishedAt:  finishedAt,
		Findings: FindingCounts{
			Total: int(scan.TotalFindings),
			BySeverity: map[string]int{
				"critical": int(scan.CriticalCount),
				"high":     int(scan.HighCount),
				"medium":   int(scan.MediumCount),
				"low":      int(scan.LowCount),
				"info":     int(scan.InfoCount),
			},
		},
		ResultURL: scan.StorageURL,
	}
	sender.PostAsync(payload)
}

// FireAgenticScan loads the agentic scan row, computes severity counts from
// associated findings, and posts a completion payload. No-op when
// settings/repo are nil or the webhook is not enabled.
func FireAgenticScan(settings *config.Settings, repo *database.Repository, agenticScanUUID string) {
	if settings == nil || repo == nil || agenticScanUUID == "" {
		return
	}
	if !settings.Notify.IsWebhookActive() {
		return
	}
	sender := NewSender(settings.Notify.Webhook)
	if sender == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	run, err := repo.GetAgenticScan(ctx, agenticScanUUID)
	if err != nil || run == nil {
		zap.L().Debug("[Notify] webhook: agentic scan not found", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(err))
		return
	}

	bySeverity := agenticSeverityCounts(ctx, repo, agenticScanUUID)
	total := 0
	for _, n := range bySeverity {
		total += n
	}
	// AgenticScan.FindingCount is the source of truth when the run set it
	// explicitly (e.g. before findings rows landed); fall back to the
	// per-row aggregate otherwise.
	if total == 0 {
		total = run.FindingCount
	}

	scanType := strings.TrimSpace(run.Mode)
	if scanType == "" {
		scanType = "agentic"
	}
	status := run.Status
	if status == "" {
		status = "completed"
	}
	finishedAt := run.CompletedAt
	if finishedAt.IsZero() {
		finishedAt = time.Now()
	}

	payload := ScanCompletedPayload{
		Event:       "scan.completed",
		ProjectUUID: run.ProjectUUID,
		ScanUUID:    run.UUID,
		ScanType:    scanType,
		Target:      run.TargetURL,
		Status:      status,
		StartedAt:   run.StartedAt,
		FinishedAt:  finishedAt,
		Findings: FindingCounts{
			Total:      total,
			BySeverity: bySeverity,
		},
		ResultURL: run.StorageURL,
	}
	sender.PostAsync(payload)
}

// agenticSeverityCounts returns finding counts grouped by severity for one
// agentic scan, with canonical severity keys (critical/high/medium/low/info)
// always present (zero if absent) so downstream JSON payload shape stays
// stable. Unknown severities are preserved verbatim.
func agenticSeverityCounts(ctx context.Context, repo *database.Repository, agenticScanUUID string) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	rows, err := database.CountFindingsByAgenticScan(ctx, repo.DB(), agenticScanUUID)
	if err != nil {
		zap.L().Debug("[Notify] webhook: severity aggregation failed", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(err))
		return counts
	}
	for key, n := range rows {
		counts[key] = int(n)
	}
	return counts
}
