package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// DatabaseStats holds database statistics
type DatabaseStats struct {
	Database     DatabaseInfo        `json:"database"`
	Records      RecordCounts        `json:"records"`
	Findings     FindingsStats       `json:"findings"`
	HTTPMethods  map[string]int64    `json:"http_methods"`
	StatusCodes  StatusCodeBreakdown `json:"status_codes"`
	Performance  PerformanceMetrics  `json:"performance"`
	DateRange    DateRangeStats      `json:"date_range"`
	ScanSessions []ScanSessionStats  `json:"scan_sessions,omitempty"`
	TopHosts     []HostStats         `json:"top_hosts,omitempty"`
}

// DatabaseInfo holds database metadata
type DatabaseInfo struct {
	Path    string `json:"path"`
	Driver  string `json:"driver"`
	Version string `json:"version,omitempty"`
	Size    int64  `json:"size"`
}

// RecordCounts holds counts of each record type
type RecordCounts struct {
	HTTPRecords     int64   `json:"http_records"`
	WithResponse    int64   `json:"with_response"`
	ResponsePercent float64 `json:"response_percent"`
	Findings        int64   `json:"findings"`
}

// FindingsStats holds finding statistics by severity
type FindingsStats struct {
	BySeverity map[string]int64 `json:"by_severity"`
	Total      int64            `json:"total"`
}

// StatusCodeBreakdown holds status code statistics
type StatusCodeBreakdown struct {
	Success   int64         `json:"success"`    // 2xx
	Redirect  int64         `json:"redirect"`   // 3xx
	ClientErr int64         `json:"client_err"` // 4xx
	ServerErr int64         `json:"server_err"` // 5xx
	ByCode    map[int]int64 `json:"by_code"`
}

// PerformanceMetrics holds response time statistics
type PerformanceMetrics struct {
	AvgResponseTime int64 `json:"avg_response_time"`
	MinResponseTime int64 `json:"min_response_time"`
	MaxResponseTime int64 `json:"max_response_time"`
	P50ResponseTime int64 `json:"p50_response_time"`
	P95ResponseTime int64 `json:"p95_response_time"`
	P99ResponseTime int64 `json:"p99_response_time"`
}

// DateRangeStats holds date range information
type DateRangeStats struct {
	FirstRequest time.Time     `json:"first_request"`
	LastRequest  time.Time     `json:"last_request"`
	Duration     time.Duration `json:"duration"`
}

// ScanSessionStats holds statistics for a scan session
type ScanSessionStats struct {
	ScanUUID       string `json:"scan_uuid"`
	Name           string `json:"name,omitempty"`
	Status         string `json:"status"`
	ProcessedCount int64  `json:"processed_count"`
	ScanMode       string `json:"scan_mode,omitempty"`
}

// HostStats holds statistics for a host
type HostStats struct {
	Scheme       string `json:"scheme"`
	Hostname     string `json:"hostname"`
	Port         int    `json:"port"`
	RequestCount int64  `json:"request_count"`
	FindingCount int64  `json:"finding_count"`
}

// GetStats retrieves database statistics
func (db *DB) GetStats(ctx context.Context, filters QueryFilters) (*DatabaseStats, error) {
	stats := &DatabaseStats{
		Database: DatabaseInfo{
			Driver: db.driver,
		},
		HTTPMethods: make(map[string]int64),
		Findings: FindingsStats{
			BySeverity: make(map[string]int64),
		},
		StatusCodes: StatusCodeBreakdown{
			ByCode: make(map[int]int64),
		},
	}

	if err := db.getRecordCounts(ctx, stats); err != nil {
		return nil, err
	}
	if err := db.getFindingsStats(ctx, stats); err != nil {
		return nil, err
	}
	if err := db.getHTTPMethodStats(ctx, stats); err != nil {
		return nil, err
	}
	if err := db.getStatusCodeStats(ctx, stats); err != nil {
		return nil, err
	}
	if err := db.getPerformanceStats(ctx, stats); err != nil {
		return nil, err
	}
	if err := db.getDateRangeStats(ctx, stats); err != nil {
		return nil, err
	}
	if err := db.getScanSessionStats(ctx, stats); err != nil {
		return nil, err
	}

	return stats, nil
}

// getRecordCounts gets counts of all record types
func (db *DB) getRecordCounts(ctx context.Context, stats *DatabaseStats) error {
	// Count HTTP records
	count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		return err
	}
	stats.Records.HTTPRecords = int64(count)

	// Count records with response
	count, err = db.NewSelect().Model((*HTTPRecord)(nil)).Where("has_response = ?", true).Count(ctx)
	if err != nil {
		return err
	}
	stats.Records.WithResponse = int64(count)

	// Calculate response percentage
	if stats.Records.HTTPRecords > 0 {
		stats.Records.ResponsePercent = float64(stats.Records.WithResponse) / float64(stats.Records.HTTPRecords) * 100
	}

	// Count findings
	count, err = db.NewSelect().Model((*Finding)(nil)).Count(ctx)
	if err != nil {
		return err
	}
	stats.Records.Findings = int64(count)

	return nil
}

// getFindingsStats gets finding statistics by severity
func (db *DB) getFindingsStats(ctx context.Context, stats *DatabaseStats) error {
	type severityCount struct {
		Severity string
		Count    int64
	}

	var results []severityCount
	err := db.NewSelect().
		Model((*Finding)(nil)).
		Column("severity").
		ColumnExpr("COUNT(*) AS count").
		Group("severity").
		Scan(ctx, &results)
	if err != nil {
		return err
	}

	for _, r := range results {
		stats.Findings.BySeverity[r.Severity] = r.Count
		stats.Findings.Total += r.Count
	}

	return nil
}

// getHTTPMethodStats gets HTTP method distribution
func (db *DB) getHTTPMethodStats(ctx context.Context, stats *DatabaseStats) error {
	type methodCount struct {
		Method string
		Count  int64
	}

	var results []methodCount
	err := db.NewSelect().
		Model((*HTTPRecord)(nil)).
		Column("method").
		ColumnExpr("COUNT(*) AS count").
		Group("method").
		Order("count DESC").
		Scan(ctx, &results)
	if err != nil {
		return err
	}

	for _, r := range results {
		stats.HTTPMethods[r.Method] = r.Count
	}

	return nil
}

// getStatusCodeStats gets status code distribution (from http_records directly)
func (db *DB) getStatusCodeStats(ctx context.Context, stats *DatabaseStats) error {
	type statusCount struct {
		StatusCode int
		Count      int64
	}

	var results []statusCount
	err := db.NewSelect().
		Model((*HTTPRecord)(nil)).
		Column("status_code").
		ColumnExpr("COUNT(*) AS count").
		Where("has_response = ?", true).
		Group("status_code").
		Order("count DESC").
		Scan(ctx, &results)
	if err != nil {
		return err
	}

	for _, r := range results {
		stats.StatusCodes.ByCode[r.StatusCode] = r.Count

		if r.StatusCode >= 200 && r.StatusCode < 300 {
			stats.StatusCodes.Success += r.Count
		} else if r.StatusCode >= 300 && r.StatusCode < 400 {
			stats.StatusCodes.Redirect += r.Count
		} else if r.StatusCode >= 400 && r.StatusCode < 500 {
			stats.StatusCodes.ClientErr += r.Count
		} else if r.StatusCode >= 500 && r.StatusCode < 600 {
			stats.StatusCodes.ServerErr += r.Count
		}
	}

	return nil
}

// getPerformanceStats gets response time statistics (from http_records directly)
func (db *DB) getPerformanceStats(ctx context.Context, stats *DatabaseStats) error {
	type perfStats struct {
		Avg float64
		Min int64
		Max int64
	}

	var result perfStats
	err := db.NewSelect().
		Model((*HTTPRecord)(nil)).
		ColumnExpr("AVG(response_time_ms) AS avg").
		ColumnExpr("MIN(response_time_ms) AS min").
		ColumnExpr("MAX(response_time_ms) AS max").
		Where("has_response = ?", true).
		Scan(ctx, &result)
	if err != nil {
		return err
	}

	stats.Performance.AvgResponseTime = int64(result.Avg)
	stats.Performance.MinResponseTime = result.Min
	stats.Performance.MaxResponseTime = result.Max

	// Single-pass percentile calculation using ROW_NUMBER window function
	withResp := stats.Records.WithResponse
	if withResp > 0 {
		p50Idx := withResp / 2
		p95Idx := withResp * 95 / 100
		p99Idx := withResp * 99 / 100

		type pRow struct {
			ResponseTimeMs int64 `bun:"response_time_ms"`
			RN             int64 `bun:"rn"`
		}
		var pRows []pRow
		err = db.NewRaw(`
			SELECT response_time_ms, rn FROM (
			    SELECT response_time_ms,
			           ROW_NUMBER() OVER (ORDER BY response_time_ms ASC) AS rn
			    FROM http_records
			    WHERE has_response = 1
			) sub
			WHERE rn IN (?, ?, ?)
		`, p50Idx, p95Idx, p99Idx).Scan(ctx, &pRows)
		if err == nil {
			for _, r := range pRows {
				switch r.RN {
				case p50Idx:
					stats.Performance.P50ResponseTime = r.ResponseTimeMs
				case p95Idx:
					stats.Performance.P95ResponseTime = r.ResponseTimeMs
				case p99Idx:
					stats.Performance.P99ResponseTime = r.ResponseTimeMs
				}
			}
		}
	}

	return nil
}

// getDateRangeStats gets date range information
func (db *DB) getDateRangeStats(ctx context.Context, stats *DatabaseStats) error {
	type dateRange struct {
		First time.Time
		Last  time.Time
	}

	var result dateRange
	err := db.NewSelect().
		Model((*HTTPRecord)(nil)).
		ColumnExpr("MIN(sent_at) AS first").
		ColumnExpr("MAX(sent_at) AS last").
		Scan(ctx, &result)
	if err != nil {
		return err
	}

	stats.DateRange.FirstRequest = result.First
	stats.DateRange.LastRequest = result.Last
	if !result.First.IsZero() && !result.Last.IsZero() {
		stats.DateRange.Duration = result.Last.Sub(result.First)
	}

	return nil
}

// getScanSessionStats gets statistics for scan sessions from the scans table
func (db *DB) getScanSessionStats(ctx context.Context, stats *DatabaseStats) error {
	var scans []Scan
	err := db.NewSelect().
		Model(&scans).
		Column("uuid", "name", "status", "processed_count", "scan_mode").
		OrderExpr("created_at DESC").
		Limit(10).
		Scan(ctx)
	if err != nil {
		return err
	}

	for _, s := range scans {
		stats.ScanSessions = append(stats.ScanSessions, ScanSessionStats{
			ScanUUID:       s.UUID,
			Name:           s.Name,
			Status:         s.Status,
			ProcessedCount: s.ProcessedCount,
			ScanMode:       s.ScanMode,
		})
	}

	return nil
}

// GetTopHosts retrieves top hosts by request count with finding counts in a single query.
func (db *DB) GetTopHosts(ctx context.Context, limit int) ([]HostStats, error) {
	type hostWithFindings struct {
		Scheme       string `bun:"scheme"`
		Hostname     string `bun:"hostname"`
		Port         int    `bun:"port"`
		RequestCount int64  `bun:"request_count"`
		FindingCount int64  `bun:"finding_count"`
	}

	var rows []hostWithFindings
	err := db.NewRaw(`
		SELECT hosts.scheme, hosts.hostname, hosts.port, hosts.request_count,
		       COALESCE(fc.finding_count, 0) AS finding_count
		FROM (
		    SELECT scheme, hostname, port, COUNT(*) AS request_count
		    FROM http_records
		    GROUP BY scheme, hostname, port
		    ORDER BY request_count DESC
		    LIMIT ?
		) AS hosts
		LEFT JOIN (
		    SELECT r.scheme, r.hostname, r.port, COUNT(DISTINCT f.id) AS finding_count
		    FROM finding_records fr
		    JOIN findings f ON f.id = fr.finding_id
		    JOIN http_records r ON r.uuid = fr.record_uuid
		    GROUP BY r.scheme, r.hostname, r.port
		) AS fc ON fc.scheme = hosts.scheme
		       AND fc.hostname = hosts.hostname
		       AND fc.port = hosts.port
	`, limit).Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}

	hostStats := make([]HostStats, 0, len(rows))
	for _, r := range rows {
		hostStats = append(hostStats, HostStats(r))
	}

	return hostStats, nil
}

// FormatStats formats statistics as a human-readable string
func FormatStats(stats *DatabaseStats) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "%s %s\n",
		terminal.SectionSymbol(),
		terminal.BoldCyan("Database Statistics"))
	sb.WriteString(terminal.Gray("═══════════════════════════════════════════════════════════════"))
	sb.WriteString("\n\n")

	fmt.Fprintf(&sb, "Driver: %s\n\n", terminal.Cyan(stats.Database.Driver))

	// Record counts
	fmt.Fprintf(&sb, "%s %s\n",
		terminal.SubSectionSymbol(),
		terminal.Bold("Records"))
	sb.WriteString(terminal.Gray("───────────────────────────────────────────────────────────────\n"))
	fmt.Fprintf(&sb, "  HTTP Records:   %s\n", terminal.Cyan(fmt.Sprintf("%d", stats.Records.HTTPRecords)))
	fmt.Fprintf(&sb, "  With Response:  %s %s\n",
		terminal.Cyan(fmt.Sprintf("%d", stats.Records.WithResponse)),
		terminal.Gray(fmt.Sprintf("(%.1f%%)", stats.Records.ResponsePercent)))
	fmt.Fprintf(&sb, "  Findings:       %s\n\n", terminal.Cyan(fmt.Sprintf("%d", stats.Records.Findings)))

	// Findings by severity
	if stats.Findings.Total > 0 {
		fmt.Fprintf(&sb, "%s %s\n",
			terminal.ResultSymbol(),
			terminal.Bold("Findings by Severity"))
		sb.WriteString(terminal.Gray("───────────────────────────────────────────────────────────────\n"))

		if count, ok := stats.Findings.BySeverity["critical"]; ok && count > 0 {
			fmt.Fprintf(&sb, "  %s Critical:     %s\n",
				terminal.CriticalSymbol(),
				terminal.BoldMagenta(fmt.Sprintf("%d", count)))
		}
		if count, ok := stats.Findings.BySeverity["high"]; ok && count > 0 {
			fmt.Fprintf(&sb, "  %s High:         %s\n",
				terminal.HighSymbol(),
				terminal.BoldRed(fmt.Sprintf("%d", count)))
		}
		if count, ok := stats.Findings.BySeverity["medium"]; ok && count > 0 {
			fmt.Fprintf(&sb, "  %s Medium:       %s\n",
				terminal.MediumSymbol(),
				terminal.BoldYellow(fmt.Sprintf("%d", count)))
		}
		if count, ok := stats.Findings.BySeverity["low"]; ok && count > 0 {
			fmt.Fprintf(&sb, "  %s Low:          %s\n",
				terminal.LowSymbol(),
				terminal.BoldGreen(fmt.Sprintf("%d", count)))
		}
		if count, ok := stats.Findings.BySeverity["info"]; ok && count > 0 {
			fmt.Fprintf(&sb, "  %s Info:         %s\n",
				terminal.InfoSeveritySymbol(),
				terminal.BoldBlue(fmt.Sprintf("%d", count)))
		}
		sb.WriteString("\n")
	}

	// HTTP methods
	if len(stats.HTTPMethods) > 0 {
		fmt.Fprintf(&sb, "%s %s\n",
			terminal.SubSectionSymbol(),
			terminal.Bold("HTTP Methods"))
		sb.WriteString(terminal.Gray("───────────────────────────────────────────────────────────────\n"))
		total := stats.Records.HTTPRecords
		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
			if count, ok := stats.HTTPMethods[method]; ok && count > 0 {
				pct := float64(count) / float64(total) * 100
				fmt.Fprintf(&sb, "  %s:%s%s %s\n",
					terminal.Cyan(method),
					strings.Repeat(" ", 10-len(method)),
					terminal.Green(fmt.Sprintf("%d", count)),
					terminal.Gray(fmt.Sprintf("(%.1f%%)", pct)))
			}
		}
		sb.WriteString("\n")
	}

	// Status codes
	if stats.Records.WithResponse > 0 {
		fmt.Fprintf(&sb, "%s %s\n",
			terminal.SubSectionSymbol(),
			terminal.Bold("Status Codes"))
		sb.WriteString(terminal.Gray("───────────────────────────────────────────────────────────────\n"))
		total := stats.Records.WithResponse
		if stats.StatusCodes.Success > 0 {
			pct := float64(stats.StatusCodes.Success) / float64(total) * 100
			fmt.Fprintf(&sb, "  2xx Success:  %s %s\n",
				terminal.Green(fmt.Sprintf("%d", stats.StatusCodes.Success)),
				terminal.Gray(fmt.Sprintf("(%.1f%%)", pct)))
		}
		if stats.StatusCodes.Redirect > 0 {
			pct := float64(stats.StatusCodes.Redirect) / float64(total) * 100
			fmt.Fprintf(&sb, "  3xx Redirect: %s %s\n",
				terminal.Cyan(fmt.Sprintf("%d", stats.StatusCodes.Redirect)),
				terminal.Gray(fmt.Sprintf("(%.1f%%)", pct)))
		}
		if stats.StatusCodes.ClientErr > 0 {
			pct := float64(stats.StatusCodes.ClientErr) / float64(total) * 100
			fmt.Fprintf(&sb, "  4xx Client:   %s %s\n",
				terminal.Yellow(fmt.Sprintf("%d", stats.StatusCodes.ClientErr)),
				terminal.Gray(fmt.Sprintf("(%.1f%%)", pct)))
		}
		if stats.StatusCodes.ServerErr > 0 {
			pct := float64(stats.StatusCodes.ServerErr) / float64(total) * 100
			fmt.Fprintf(&sb, "  5xx Server:   %s %s\n",
				terminal.Red(fmt.Sprintf("%d", stats.StatusCodes.ServerErr)),
				terminal.Gray(fmt.Sprintf("(%.1f%%)", pct)))
		}
		sb.WriteString("\n")
	}

	// Performance
	if stats.Records.WithResponse > 0 {
		fmt.Fprintf(&sb, "%s %s\n",
			terminal.SubSectionSymbol(),
			terminal.Bold("Performance"))
		sb.WriteString(terminal.Gray("───────────────────────────────────────────────────────────────\n"))
		fmt.Fprintf(&sb, "  Avg Response Time:   %s\n",
			terminal.Cyan(fmt.Sprintf("%dms", stats.Performance.AvgResponseTime)))
		fmt.Fprintf(&sb, "  Min Response Time:   %s\n",
			terminal.Green(fmt.Sprintf("%dms", stats.Performance.MinResponseTime)))
		fmt.Fprintf(&sb, "  Max Response Time:   %s\n",
			terminal.Yellow(fmt.Sprintf("%dms", stats.Performance.MaxResponseTime)))
		if stats.Performance.P50ResponseTime > 0 {
			fmt.Fprintf(&sb, "  P50 Response Time:   %s\n",
				terminal.Cyan(fmt.Sprintf("%dms", stats.Performance.P50ResponseTime)))
		}
		if stats.Performance.P95ResponseTime > 0 {
			fmt.Fprintf(&sb, "  P95 Response Time:   %s\n",
				terminal.Yellow(fmt.Sprintf("%dms", stats.Performance.P95ResponseTime)))
		}
		if stats.Performance.P99ResponseTime > 0 {
			fmt.Fprintf(&sb, "  P99 Response Time:   %s\n",
				terminal.Red(fmt.Sprintf("%dms", stats.Performance.P99ResponseTime)))
		}
		sb.WriteString("\n")
	}

	// Date range
	if !stats.DateRange.FirstRequest.IsZero() {
		fmt.Fprintf(&sb, "%s %s\n",
			terminal.SubSectionSymbol(),
			terminal.Bold("Date Range"))
		sb.WriteString(terminal.Gray("───────────────────────────────────────────────────────────────\n"))
		fmt.Fprintf(&sb, "  First Request:  %s\n",
			terminal.Cyan(stats.DateRange.FirstRequest.Format("2006-01-02 15:04:05")))
		fmt.Fprintf(&sb, "  Last Request:   %s\n",
			terminal.Cyan(stats.DateRange.LastRequest.Format("2006-01-02 15:04:05")))
		fmt.Fprintf(&sb, "  Duration:       %s\n\n",
			terminal.Green(formatDuration(stats.DateRange.Duration)))
	}

	// Scan sessions
	if len(stats.ScanSessions) > 0 {
		fmt.Fprintf(&sb, "%s %s\n",
			terminal.SubSectionSymbol(),
			terminal.Bold("Scan Sessions"))
		sb.WriteString(terminal.Gray("───────────────────────────────────────────────────────────────\n"))
		for _, s := range stats.ScanSessions {
			name := s.ScanUUID
			if s.Name != "" {
				name = s.Name
			}
			mode := ""
			if s.ScanMode != "" {
				mode = fmt.Sprintf(" [%s]", s.ScanMode)
			}
			fmt.Fprintf(&sb, "  %s: %s %s%s\n",
				terminal.Cyan(name),
				terminal.Green(fmt.Sprintf("%d processed", s.ProcessedCount)),
				terminal.Gray(s.Status),
				terminal.Gray(mode))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%d days, %d hours", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%d hours, %d minutes", hours, minutes)
	}
	return fmt.Sprintf("%d minutes", minutes)
}
