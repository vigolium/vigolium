package output

import (
	"bufio"
	"encoding/json"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/public"
)

// HTMLReportMeta carries metadata for the HTML report generation.
type HTMLReportMeta struct {
	Title           string
	Version         string
	ScanDuration    string
	ScanTarget      string
	GeneratedAt     string
	ReportSharedURL string
}

// HTMLReportData is the template data passed to template.html.
type HTMLReportData struct {
	Title           string
	GeneratedAt     string
	ScanDuration    string
	ScanTarget      string
	VigoliumVersion string
	ReportSharedURL string
	ResultsJSON     template.JS
}

// resolveReportSharedURL returns meta.ReportSharedURL when set, falling back to
// the VIGOLIUM_REPORT_SHARED_URL environment variable. The React template
// substitutes its own default when the value is empty.
func resolveReportSharedURL(meta HTMLReportMeta) string {
	if meta.ReportSharedURL != "" {
		return meta.ReportSharedURL
	}
	return os.Getenv("VIGOLIUM_REPORT_SHARED_URL")
}

// GenerateHTMLReport renders the embedded template.html template
// with the provided items to outputPath. If title is empty it defaults
// to "Vigolium Scan Report".
//
// Each item should be a ready-to-marshal envelope (e.g. struct with
// Type and Data fields). Items are streamed one at a time to keep
// memory usage constant regardless of result set size.
func GenerateHTMLReport(items []any, outputPath string, meta HTMLReportMeta) error {
	title := meta.Title
	if title == "" {
		title = "Vigolium Scan Report"
	}

	// Read embedded template
	tmplBytes, err := public.StaticFS.ReadFile("static-reports/template.html")
	if err != nil {
		return err
	}

	// Split template at the {{.ResultsJSON}} marker so we can stream
	// JSON rows directly instead of holding the entire array in memory.
	const marker = "{{.ResultsJSON}}"
	tmplStr := string(tmplBytes)
	parts := strings.SplitN(tmplStr, marker, 2)

	if len(parts) != 2 {
		// Marker not found — fall back to monolithic marshal
		return generateHTMLReportLegacy(items, outputPath, meta, tmplStr)
	}

	// Create output file with buffered writer
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	w := bufio.NewWriter(f)

	// Replace placeholders in the "before" portion with simple string
	// substitution. We avoid template.Parse because the bundled JS in the
	// template contains sequences (e.g. "{{") that break both html/template
	// and text/template parsers.
	generatedAt := meta.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	before := strings.Replace(parts[0], "{{.Title}}", title, 1)
	before = strings.Replace(before, "{{.GeneratedAt}}", generatedAt, 1)
	before = strings.Replace(before, "{{.ScanDuration}}", meta.ScanDuration, 1)
	before = strings.Replace(before, "{{.ScanTarget}}", meta.ScanTarget, 1)
	before = strings.Replace(before, "{{.VigoliumVersion}}", meta.Version, 1)
	before = strings.Replace(before, "{{.ReportSharedURL}}", resolveReportSharedURL(meta), 1)
	if _, err := w.WriteString(before); err != nil {
		return err
	}

	// Stream JSON array: write each item (already an envelope)
	if err := w.WriteByte('['); err != nil {
		return err
	}
	for i, item := range items {
		if i > 0 {
			if err := w.WriteByte(','); err != nil {
				return err
			}
		}
		b, err := json.Marshal(item)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	if err := w.WriteByte(']'); err != nil {
		return err
	}

	// Write the "after" portion as-is (no placeholders to substitute)
	if _, err := w.WriteString(parts[1]); err != nil {
		return err
	}

	return w.Flush()
}

// generateHTMLReportLegacy is the original monolithic approach, used as a
// fallback when the template doesn't contain the expected marker.
func generateHTMLReportLegacy(items []any, outputPath string, meta HTMLReportMeta, tmplStr string) error {
	rowsJSON, err := json.Marshal(items)
	if err != nil {
		return err
	}

	tmpl, err := template.New("report").Parse(tmplStr)
	if err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	title := meta.Title
	if title == "" {
		title = "Vigolium Scan Report"
	}

	generatedAt := meta.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}

	return tmpl.Execute(f, HTMLReportData{
		Title:           title,
		GeneratedAt:     generatedAt,
		ScanDuration:    meta.ScanDuration,
		ScanTarget:      meta.ScanTarget,
		VigoliumVersion: meta.Version,
		ReportSharedURL: resolveReportSharedURL(meta),
		ResultsJSON:     template.JS(rowsJSON),
	})
}
