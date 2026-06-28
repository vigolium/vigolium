package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/fsexport"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// This file implements the one-shot `fs` output format: a flat, browsable
// filesystem tree of HTTP traffic and findings, laid out so a coding agent (or
// a human with nothing but `ls`/`grep`/`jq`) can reason about a scan without a
// database. The layout and per-record/per-finding rendering live in the shared
// pkg/fsexport package, which the server's live --mirror-fs writer also uses.
//
// Two sibling directories are written off a base path (-o, or "vigolium" in the
// cwd when no -o is given):
//
//	<base>-traffic/
//	  index.json                       # one compact record per request (jq-friendly array)
//	  <host>/0001.req                  # "@target <scheme>://<host>" + the raw request
//	  <host>/0001.resp.headers         # status line + response headers
//	  <host>/0001.resp.body            # response body, gzip-decoded so it greps clean
//	<base>-findings/
//	  index.json                       # one compact entry per finding
//	  <host>/0001.md                   # the finding, cross-linked to its .req file
//
// Per-host ids are zero-padded sequences assigned in sent_at order, so a
// re-export of the same data is reproducible.

// fsExportOptions tunes a single fs export.
type fsExportOptions struct {
	omitResponse bool // drop .resp.* files (mirrors --omit-response)
}

// fsExportStats summarizes what an fs export wrote, for the caller's summary line.
type fsExportStats struct {
	Traffic     int
	Findings    int
	Hosts       int
	TrafficDir  string
	FindingsDir string
}

// writeFSExport reads http_records and findings (filtered by `filters`) and
// writes the flat filesystem tree described above, rooted at `base`. The two
// passes run in order: traffic first (it builds the uuid→"host/id" map), then
// findings (which cross-link back into traffic and backfill the traffic index's
// per-record top severity). Records and findings are streamed with a row cursor,
// so only the small index entries — not the raw bodies — accumulate in memory.
func writeFSExport(ctx context.Context, db *database.DB, filters database.QueryFilters, base string, opts fsExportOptions) (fsExportStats, error) {
	base = fsResolveBase(base)
	trafficRoot := base + "-traffic"
	findingsRoot := base + "-findings"
	trafficDirBase := filepath.Base(base) + "-traffic"

	stats := fsExportStats{}
	hosts := make(map[string]struct{})

	// --- Traffic pass ---
	trafficSeq := make(map[string]int)
	var trafficEntries []fsexport.TrafficEntry
	trafficByUUID := make(map[string]int) // record uuid → index in trafficEntries
	uuidToPath := make(map[string]string) // record uuid → "host/id" (for finding links)
	trafficCreated := false

	recFilters := filters
	recFilters.SortBy = "sent_at"
	recFilters.SortAsc = true
	recQuery := database.NewQueryBuilder(db, recFilters).BuildRecordsQuery().OrderExpr("r.uuid ASC")
	if opts.omitResponse {
		recQuery = recQuery.ExcludeColumn("raw_response")
	}
	rows, err := recQuery.Rows(ctx)
	if err != nil {
		return stats, fmt.Errorf("query HTTP records: %w", err)
	}
	for rows.Next() {
		rec := new(database.HTTPRecord)
		if err := db.ScanRow(ctx, rows, rec); err != nil {
			_ = rows.Close()
			return stats, fmt.Errorf("scan HTTP record: %w", err)
		}
		if len(rec.RawRequest) == 0 {
			continue
		}
		host := fsexport.SanitizeHost(rec.Hostname)
		hosts[host] = struct{}{}
		dir := filepath.Join(trafficRoot, host)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			_ = rows.Close()
			return stats, fmt.Errorf("create traffic dir %s: %w", dir, err)
		}
		trafficCreated = true
		trafficSeq[host]++
		id := fmt.Sprintf("%04d", trafficSeq[host])

		// .req — "@target ..." line then the raw request verbatim.
		if err := os.WriteFile(filepath.Join(dir, id+".req"), fsexport.RequestBytes(rec), 0o644); err != nil {
			_ = rows.Close()
			return stats, fmt.Errorf("write %s.req: %w", id, err)
		}

		status, bodyLen, err := fsexport.WriteResponseFiles(dir, id, rec, opts.omitResponse)
		if err != nil {
			_ = rows.Close()
			return stats, fmt.Errorf("write %s response: %w", id, err)
		}

		relPath := host + "/" + id
		uuidToPath[rec.UUID] = relPath
		trafficByUUID[rec.UUID] = len(trafficEntries)
		trafficEntries = append(trafficEntries, fsexport.TrafficEntry{
			ID:          id,
			Host:        rec.Hostname,
			Path:        relPath,
			Method:      rec.Method,
			URL:         rec.Path,
			Status:      status,
			ContentType: fsexport.CleanContentType(rec.ResponseContentType),
			Bytes:       bodyLen,
		})
	}
	if cerr := rows.Err(); cerr != nil {
		_ = rows.Close()
		return stats, fmt.Errorf("read HTTP records: %w", cerr)
	}
	_ = rows.Close()
	stats.Traffic = len(trafficEntries)

	// --- Findings pass ---
	findingSeq := make(map[string]int)
	var findingEntries []fsexport.FindingEntry
	recTopSeverity := make(map[string]string) // record uuid → highest finding severity
	findingsCreated := false

	fq := db.NewSelect().Model((*database.Finding)(nil)).OrderExpr("found_at ASC, id ASC")
	if filters.ProjectUUID != "" {
		fq = fq.Where("project_uuid = ?", filters.ProjectUUID)
	}
	if filters.HostPattern != "" {
		fq = fq.Where("hostname LIKE ?", fsLikePattern(filters.HostPattern))
	}
	if len(filters.Severity) > 0 {
		sevs := make([]string, len(filters.Severity))
		for i, s := range filters.Severity {
			sevs[i] = strings.ToLower(strings.TrimSpace(s))
		}
		fq = fq.Where("LOWER(severity) IN (?)", bun.List(sevs))
	}
	if term := fsSearchTerm(filters); term != "" {
		p := "%" + term + "%"
		fq = fq.Where("(module_id LIKE ? OR module_name LIKE ? OR description LIKE ? OR url LIKE ? OR hostname LIKE ?)", p, p, p, p, p)
	}
	if filters.Limit > 0 {
		fq = fq.Limit(filters.Limit)
	}
	frows, err := fq.Rows(ctx)
	if err != nil {
		return stats, fmt.Errorf("query findings: %w", err)
	}
	for frows.Next() {
		f := new(database.Finding)
		if err := db.ScanRow(ctx, frows, f); err != nil {
			_ = frows.Close()
			return stats, fmt.Errorf("scan finding: %w", err)
		}
		host := fsexport.SanitizeHost(fsexport.FindingHost(f))
		hosts[host] = struct{}{}
		dir := filepath.Join(findingsRoot, host)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			_ = frows.Close()
			return stats, fmt.Errorf("create findings dir %s: %w", dir, err)
		}
		findingsCreated = true
		findingSeq[host]++
		id := fmt.Sprintf("%04d", findingSeq[host])

		// Resolve linked traffic that made it into this export, reading back the
		// .req/.resp files we just wrote so the finding markdown can embed them inline.
		var linked []fsexport.LinkedRecord
		var linkedPaths []string
		for _, u := range f.HTTPRecordUUIDs {
			if p, ok := uuidToPath[u]; ok {
				linked = append(linked, fsexport.ReadLinkedRecord(trafficRoot, p, opts.omitResponse))
				linkedPaths = append(linkedPaths, p)
				recTopSeverity[u] = fsexport.MaxSeverity(recTopSeverity[u], f.Severity)
			}
		}

		md := fsexport.RenderFindingMarkdown(f, linked, trafficDirBase)
		if err := os.WriteFile(filepath.Join(dir, id+".md"), md, 0o644); err != nil {
			_ = frows.Close()
			return stats, fmt.Errorf("write %s.md: %w", id, err)
		}

		title := f.ModuleName
		if title == "" {
			title = f.ModuleID
		}
		findingEntries = append(findingEntries, fsexport.FindingEntry{
			ID:         id,
			Host:       fsexport.FindingHost(f),
			Path:       host + "/" + id + ".md",
			Severity:   f.Severity,
			Confidence: f.Confidence,
			Module:     f.ModuleID,
			Title:      title,
			URL:        f.URL,
			Traffic:    linkedPaths,
		})
	}
	if cerr := frows.Err(); cerr != nil {
		_ = frows.Close()
		return stats, fmt.Errorf("read findings: %w", cerr)
	}
	_ = frows.Close()
	stats.Findings = len(findingEntries)
	stats.Hosts = len(hosts)

	// Backfill the traffic index's per-record top severity now that findings are known.
	for uuid, sev := range recTopSeverity {
		if idx, ok := trafficByUUID[uuid]; ok {
			s := sev
			trafficEntries[idx].Finding = &s
		}
	}

	// Write the index files into whichever roots actually got created.
	if trafficCreated {
		if err := fsWriteIndex(filepath.Join(trafficRoot, "index.json"), trafficEntries); err != nil {
			return stats, err
		}
		stats.TrafficDir = trafficRoot
	}
	if findingsCreated {
		if err := fsWriteIndex(filepath.Join(findingsRoot, "index.json"), findingEntries); err != nil {
			return stats, err
		}
		stats.FindingsDir = findingsRoot
	}

	return stats, nil
}

// fsWriteIndex marshals entries to an indented JSON array at path. A nil slice
// is written as an empty array (not "null") so jq always sees a list.
func fsWriteIndex(path string, entries any) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal index: %w", err)
	}
	if string(data) == "null" {
		data = []byte("[]")
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// fsResolveBase strips any known format extension from the operator's -o value
// and defaults to "vigolium" (in the cwd) when no output was given.
func fsResolveBase(output string) string {
	base := types.StripFormatExtension(strings.TrimSpace(output))
	if base == "" {
		base = "vigolium"
	}
	return base
}

// fsSearchTerm picks the fuzzy/search term to filter findings by, preferring the
// broad fuzzy term.
func fsSearchTerm(filters database.QueryFilters) string {
	if filters.FuzzyTerm != "" {
		return filters.FuzzyTerm
	}
	return filters.SearchTerm
}

// fsLikePattern turns a host filter into a SQL LIKE pattern: explicit "*"
// wildcards map to "%", an otherwise literal pattern is wrapped in "%…%".
func fsLikePattern(p string) string {
	if strings.Contains(p, "*") {
		return strings.ReplaceAll(p, "*", "%")
	}
	return "%" + p + "%"
}

// fsPrintSummary writes the operator-facing summary for an fs export.
func fsPrintSummary(stats fsExportStats) {
	fmt.Fprintf(os.Stderr, "\n%s Export summary (format: %s)\n", terminal.InfoSymbol(), terminal.Cyan("fs"))
	if stats.TrafficDir != "" {
		fmt.Fprintf(os.Stderr, "  %-20s %s (%d records)\n", "Traffic", terminal.Cyan(stats.TrafficDir), stats.Traffic)
	}
	if stats.FindingsDir != "" {
		fmt.Fprintf(os.Stderr, "  %-20s %s (%d findings)\n", "Findings", terminal.Cyan(stats.FindingsDir), stats.Findings)
	}
	if stats.TrafficDir == "" && stats.FindingsDir == "" {
		fmt.Fprintf(os.Stderr, "  %s\n", "Nothing to export (no matching records or findings)")
	}
}
