package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var (
	topExportFormat string
	topExportOutput string
	topExportOnly   []string
	topExportLite   bool
	topExportSearch string
	topExportLimit  int
)

// validExportTypes lists all accepted --only values.
var validExportTypes = []string{"http", "findings", "scans", "modules", "oast", "source-repos", "scopes"}

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export database tables and module registry",
	RunE:  runExportCmd,
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVar(&topExportFormat, "format", "jsonl", "Export format: html, jsonl")
	exportCmd.Flags().StringVarP(&topExportOutput, "output", "o", "", "Output file path (required for html)")
	exportCmd.Flags().StringSliceVar(&topExportOnly, "only", nil,
		"Export only these tables (repeatable: http, findings, scans, modules, oast, source-repos, scopes)")
	exportCmd.Flags().BoolVar(&topExportLite, "lite", false,
		"Export summary fields only, omit raw HTTP data and headers")
	exportCmd.Flags().StringVar(&topExportSearch, "search", "",
		"Fuzzy search filter across URLs, paths, hostnames, methods, content types, and sources")
	exportCmd.Flags().IntVar(&topExportLimit, "limit", 0,
		"Maximum number of records to export per table (0 = unlimited)")
}

// shouldExport returns true if the given data type should be included in the export.
// When topExportOnly is empty, all types are exported.
func shouldExport(dataType string) bool {
	if len(topExportOnly) == 0 {
		return true
	}
	for _, t := range topExportOnly {
		if strings.EqualFold(t, dataType) {
			return true
		}
	}
	return false
}

// topExportRecord is the JSONL schema for HTTP record entries.
type topExportRecord struct {
	URL           string   `json:"url"`
	Method        string   `json:"method"`
	StatusCode    int      `json:"status_code"`
	ContentType   string   `json:"content_type,omitempty"`
	ContentLength int64    `json:"content_length"`
	Title         string   `json:"title,omitempty"`
	Domain        string   `json:"domain"`
	Source        string   `json:"source,omitempty"`
	Remarks       []string `json:"remarks,omitempty"`
}

// exportEnvelope wraps each exported item with a type tag for JSONL output.
type exportEnvelope struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func runExportCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	// Validate --only values
	if len(topExportOnly) > 0 {
		valid := make(map[string]bool, len(validExportTypes))
		for _, v := range validExportTypes {
			valid[v] = true
		}
		for _, t := range topExportOnly {
			if !valid[strings.ToLower(t)] {
				return fmt.Errorf("invalid --only value %q; valid values: %s", t, strings.Join(validExportTypes, ", "))
			}
		}
	}

	if topExportFormat == "html" && topExportOutput == "" {
		return fmt.Errorf("--format html requires -o/--output to specify the report file path")
	}

	switch topExportFormat {
	case "html":
		return runExportHTML()
	case "jsonl":
		return runExportJSONL()
	default:
		return fmt.Errorf("unsupported format %q; valid formats: html, jsonl", topExportFormat)
	}
}

func runExportHTML() error {
	db, err := getDB()
	if err != nil {
		return err
	}
	defer closeDatabaseOnExit()

	ctx := context.Background()
	items, err := queryExportData(ctx, db)
	if err != nil {
		return err
	}

	meta := output.HTMLReportMeta{
		Title:        "Vigolium Static Report",
		Version:      getVersion(),
		ScanDuration: computeScanDuration(ctx, db),
	}
	if err := output.GenerateHTMLReport(items, topExportOutput, meta); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s HTML report written to %s (%d records)\n",
		terminal.InfoSymbol(), terminal.Cyan(topExportOutput), len(items))
	return nil
}

// computeScanDuration queries the most recent completed scan and returns a
// human-readable duration string (e.g. "2m30s"). Returns "" if no completed
// scan is found.
func computeScanDuration(ctx context.Context, db *database.DB) string {
	var scan database.Scan
	err := db.NewSelect().Model(&scan).
		Column("started_at", "finished_at").
		Where("status = ?", "completed").
		OrderExpr("created_at DESC").
		Limit(1).
		Scan(ctx)
	if err != nil || scan.FinishedAt.IsZero() {
		return ""
	}
	d := scan.FinishedAt.Sub(scan.StartedAt)
	if d <= 0 {
		return ""
	}
	return d.Round(time.Millisecond).String()
}

func runExportJSONL() error {
	// Modules don't need DB access, so handle the modules-only case without opening DB.
	needsDB := shouldExport("http") || shouldExport("findings") || shouldExport("scans") ||
		shouldExport("oast") || shouldExport("source-repos") || shouldExport("scopes")

	var db *database.DB
	if needsDB {
		var err error
		db, err = getDB()
		if err != nil {
			return err
		}
		defer closeDatabaseOnExit()
	}

	ctx := context.Background()
	items, err := queryExportData(ctx, db)
	if err != nil {
		return err
	}

	// Open output writer
	var w *os.File
	if topExportOutput != "" {
		f, err := os.Create(topExportOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	} else {
		w = os.Stdout
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return fmt.Errorf("failed to encode record: %w", err)
		}
	}

	if topExportOutput != "" {
		fmt.Fprintf(os.Stderr, "%s JSONL written to %s (%d records)\n",
			terminal.InfoSymbol(), terminal.Cyan(topExportOutput), len(items))
	}
	return nil
}

// queryExportData queries all enabled tables and returns a slice of exportEnvelope
// items ready for serialization. Both HTML and JSONL paths share this function.
func queryExportData(ctx context.Context, db *database.DB) ([]any, error) {
	var items []any

	// --- Scans ---
	if shouldExport("scans") && db != nil {
		var scans []*database.Scan
		q := db.NewSelect().Model(&scans).OrderExpr("created_at DESC")
		if topExportSearch != "" {
			p := "%" + topExportSearch + "%"
			q = q.Where("(uuid LIKE ? OR status LIKE ? OR error_message LIKE ?)", p, p, p)
		}
		if topExportLimit > 0 {
			q = q.Limit(topExportLimit)
		}
		if err := q.Scan(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query scans: %v\n", terminal.WarningSymbol(), err)
		} else {
			for _, s := range scans {
				items = append(items, exportEnvelope{Type: "scan", Data: s})
			}
		}
	}

	// --- HTTP Records ---
	if shouldExport("http") && db != nil {
		qb := database.NewQueryBuilder(db, database.QueryFilters{
			FuzzyTerm: topExportSearch,
			Limit:     topExportLimit,
		})
		records, err := qb.Execute(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query HTTP records: %v\n", terminal.WarningSymbol(), err)
		} else {
			seen := make(map[string]struct{}, len(records))
			for _, r := range records {
				if _, dup := seen[r.URL]; dup {
					continue
				}
				seen[r.URL] = struct{}{}

				var data any
				if topExportLite {
					data = topExportRecord{
						URL:           r.URL,
						Method:        r.Method,
						StatusCode:    r.StatusCode,
						ContentType:   r.ResponseContentType,
						ContentLength: r.ResponseContentLength,
						Title:         r.ResponseTitle,
						Domain:        r.Hostname,
						Source:        r.Source,
						Remarks:       r.Remarks,
					}
				} else {
					// Nil out large body fields to keep report size reasonable;
					// the detail panel uses raw_request/raw_response instead.
					r.RequestBody = nil
					r.ResponseBody = nil
					data = r
				}
				items = append(items, exportEnvelope{Type: "http_record", Data: data})
			}
		}
	}

	// --- Findings ---
	if shouldExport("findings") && db != nil {
		var findings []*database.Finding
		q := db.NewSelect().Model(&findings).OrderExpr("found_at DESC")
		if topExportSearch != "" {
			p := "%" + topExportSearch + "%"
			q = q.Where("(module_name LIKE ? OR description LIKE ? OR matched_at LIKE ? OR severity LIKE ?)", p, p, p, p)
		}
		if topExportLimit > 0 {
			q = q.Limit(topExportLimit)
		}
		if err := q.Scan(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query findings: %v\n", terminal.WarningSymbol(), err)
		} else {
			for _, f := range findings {
				items = append(items, exportEnvelope{Type: "finding", Data: f})
			}
		}
	}

	// --- Modules (in-memory registry, no DB needed) ---
	if shouldExport("modules") {
		emCfg := loadEnabledModulesConfig()

		for _, m := range modules.GetActiveModules() {
			entry := moduleJSONEntry{
				ID:                   m.ID(),
				Name:                 m.Name(),
				Type:                 "active",
				Description:          m.Description(),
				ShortDescription:     m.ShortDescription(),
				ConfirmationCriteria: m.ConfirmationCriteria(),
				Severity:             m.Severity().String(),
				Confidence:           m.Confidence().String(),
				ScanScope:            scanScopeNames(m.ScanScopes()),
				Enabled:              isModuleEnabled(m.ID(), emCfg.ActiveModules),
			}
			items = append(items, exportEnvelope{Type: "module", Data: entry})
		}
		for _, m := range modules.GetPassiveModules() {
			entry := moduleJSONEntry{
				ID:                   m.ID(),
				Name:                 m.Name(),
				Type:                 "passive",
				Description:          m.Description(),
				ShortDescription:     m.ShortDescription(),
				ConfirmationCriteria: m.ConfirmationCriteria(),
				Severity:             m.Severity().String(),
				Confidence:           m.Confidence().String(),
				ScanScope:            scanScopeNames(m.ScanScopes()),
				Enabled:              isModuleEnabled(m.ID(), emCfg.PassiveModules),
			}
			items = append(items, exportEnvelope{Type: "module", Data: entry})
		}
	}

	// --- OAST Interactions ---
	if shouldExport("oast") && db != nil {
		var interactions []*database.OASTInteraction
		q := db.NewSelect().Model(&interactions).OrderExpr("interacted_at DESC")
		if topExportSearch != "" {
			p := "%" + topExportSearch + "%"
			q = q.Where("(protocol LIKE ? OR module_id LIKE ? OR unique_id LIKE ? OR full_id LIKE ? OR target_url LIKE ?)", p, p, p, p, p)
		}
		if topExportLimit > 0 {
			q = q.Limit(topExportLimit)
		}
		if err := q.Scan(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query OAST interactions: %v\n", terminal.WarningSymbol(), err)
		} else {
			for _, i := range interactions {
				items = append(items, exportEnvelope{Type: "oast_interaction", Data: i})
			}
		}
	}

	// --- Source Repos ---
	if shouldExport("source-repos") && db != nil {
		var repos []*database.SourceRepo
		q := db.NewSelect().Model(&repos).OrderExpr("created_at DESC")
		if topExportSearch != "" {
			p := "%" + topExportSearch + "%"
			q = q.Where("(name LIKE ? OR hostname LIKE ? OR root_path LIKE ? OR language LIKE ?)", p, p, p, p)
		}
		if topExportLimit > 0 {
			q = q.Limit(topExportLimit)
		}
		if err := q.Scan(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query source repos: %v\n", terminal.WarningSymbol(), err)
		} else {
			for _, r := range repos {
				items = append(items, exportEnvelope{Type: "source_repo", Data: r})
			}
		}
	}

	// --- Scopes ---
	if shouldExport("scopes") && db != nil {
		var scopes []*database.Scope
		q := db.NewSelect().Model(&scopes).Where("enabled = ?", true).OrderExpr("priority ASC")
		if topExportSearch != "" {
			p := "%" + topExportSearch + "%"
			q = q.Where("(name LIKE ? OR host_pattern LIKE ? OR path_pattern LIKE ?)", p, p, p)
		}
		if topExportLimit > 0 {
			q = q.Limit(topExportLimit)
		}
		if err := q.Scan(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to query scopes: %v\n", terminal.WarningSymbol(), err)
		} else {
			for _, s := range scopes {
				items = append(items, exportEnvelope{Type: "scope", Data: s})
			}
		}
	}

	return items, nil
}
