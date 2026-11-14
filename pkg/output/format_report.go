package output

import (
	"bytes"
	"encoding/json"
	"github.com/vigolium/vigolium/internal/redact"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/utils/textutil"
	"github.com/vigolium/vigolium/public"
	"github.com/yuin/goldmark"
)

type ReportFinding struct {
	ID              int
	Title           string
	ModuleID        string
	ModuleName      string
	Description     string
	DescriptionHTML template.HTML
	// ModuleTitle is the module's own Name(), kept separate because ModuleName
	// above holds the *display* name — parseFinding prefers the module's short
	// description there, which reads as a sentence. A renderer that needs a
	// compact label (SARIF's reportingDescriptor.name) wants this one.
	ModuleTitle        string
	Severity           string
	Confidence         string
	CWE                string
	CVSSScore          float64
	Remediation        string
	URL                string
	MatchedAt          []string
	ExtractedResults   []string
	Request            string
	Response           string
	AdditionalEvidence []string
	Tags               []string
	FoundAt            string
	FindingHash        string
	SourceFile         string
	RepoName           string
	// ScanUUID and RecordUUIDs tie the finding back to its scan and its stored
	// HTTP exchanges, so a report reader (human or agent) can fetch the full
	// evidence with `vigolium traffic body --uuid <record>`.
	ScanUUID    string
	RecordUUIDs []string
	// Hostname, Status and CreatedAt come straight from the finding row; the
	// tabular renderers (csv, junit, github) key and filter on them.
	Hostname  string
	Status    string
	CreatedAt string
}

type ReportModule struct {
	ID       string
	Name     string
	Type     string
	Severity string
	// Description and ShortDescription are carried for renderers that describe
	// the rule behind a finding rather than the finding itself (SARIF's
	// reportingDescriptor). They are only populated when the export included
	// module envelopes — `vigolium export` drops them by default (--exclude
	// module) — so every consumer must treat them as optional.
	Description      string
	ShortDescription string
}

type ReportData struct {
	Title            string
	GeneratedAt      string
	ScanDuration     string
	VigoliumVersion  string
	Target           string
	TotalFindings    int
	TotalRequests    int
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	InfoCount        int
	ActiveModules    int
	PassiveModules   int
	CriticalFindings []ReportFinding
	HighFindings     []ReportFinding
	MediumFindings   []ReportFinding
	LowFindings      []ReportFinding
	InfoFindings     []ReportFinding
	Modules          []ReportModule
}

func GenerateDocumentReport(items []any, outputPath string, meta HTMLReportMeta) error {
	title := meta.Title
	if title == "" {
		title = "Vigolium Scan Report"
	}

	tmplBytes, err := public.StaticFS.ReadFile("static-reports/report-template.html")
	if err != nil {
		return err
	}

	funcMap := template.FuncMap{
		"inc": func(i int) int { return i + 1 },
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(string(tmplBytes))
	if err != nil {
		return err
	}

	data := buildReportData(items, title, meta)

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return tmpl.Execute(f, data)
}

func buildReportData(items []any, title string, meta HTMLReportMeta) ReportData {
	generatedAt := meta.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format("2006-01-02 15:04 UTC")
	}
	rd := ReportData{
		Title:           title,
		GeneratedAt:     generatedAt,
		ScanDuration:    meta.ScanDuration,
		Target:          meta.ScanTarget,
		VigoliumVersion: meta.Version,
	}

	md := goldmark.New()

	for _, item := range items {
		raw, err := json.Marshal(item)
		if err != nil {
			continue
		}

		var envelope struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			continue
		}

		switch envelope.Type {
		case "finding":
			rf := parseFinding(envelope.Data, md)
			if !meta.NoRedact {
				redactReportFinding(&rf, meta.RedactHeaders)
			}
			switch strings.ToLower(rf.Severity) {
			case "critical":
				rd.CriticalFindings = append(rd.CriticalFindings, rf)
				rd.CriticalCount++
			case "high":
				rd.HighFindings = append(rd.HighFindings, rf)
				rd.HighCount++
			case "medium":
				rd.MediumFindings = append(rd.MediumFindings, rf)
				rd.MediumCount++
			case "low":
				rd.LowFindings = append(rd.LowFindings, rf)
				rd.LowCount++
			default:
				rd.InfoFindings = append(rd.InfoFindings, rf)
				rd.InfoCount++
			}
			rd.TotalFindings++

		case "scan":
			var scan struct {
				Target        string `json:"target"`
				TotalRequests int    `json:"total_requests"`
			}
			// best-effort: a malformed scan envelope simply leaves summary counters at zero.
			_ = json.Unmarshal(envelope.Data, &scan)
			if scan.Target != "" {
				rd.Target = scan.Target
			}
			rd.TotalRequests = scan.TotalRequests

		case "module":
			var mod struct {
				ID               string `json:"id"`
				Name             string `json:"name"`
				Type             string `json:"type"`
				Severity         string `json:"severity"`
				Description      string `json:"description"`
				ShortDescription string `json:"short_description"`
				Enabled          bool   `json:"enabled"`
			}
			if err := json.Unmarshal(envelope.Data, &mod); err == nil && mod.Enabled {
				rd.Modules = append(rd.Modules, ReportModule{
					ID:               mod.ID,
					Name:             mod.Name,
					Type:             mod.Type,
					Severity:         mod.Severity,
					Description:      mod.Description,
					ShortDescription: mod.ShortDescription,
				})
				switch mod.Type {
				case "active":
					rd.ActiveModules++
				case "passive":
					rd.PassiveModules++
				}
			}

		case "http_record":
			rd.TotalRequests++
		}
	}

	return rd
}

func parseFinding(data json.RawMessage, md goldmark.Markdown) ReportFinding {
	var f struct {
		ID                 int      `json:"id"`
		ModuleID           string   `json:"module_id"`
		ModuleName         string   `json:"module_name"`
		ModuleShort        string   `json:"module_short"`
		Description        string   `json:"description"`
		Severity           string   `json:"severity"`
		Confidence         string   `json:"confidence"`
		CWE                string   `json:"cwe_id"`
		CVSSScore          float64  `json:"cvss_score"`
		Remediation        string   `json:"remediation"`
		URL                string   `json:"url"`
		MatchedAt          []string `json:"matched_at"`
		ExtractedResults   []string `json:"extracted_results"`
		Request            string   `json:"request"`
		Response           string   `json:"response"`
		AdditionalEvidence []string `json:"additional_evidence"`
		Tags               []string `json:"tags"`
		FoundAt            string   `json:"found_at"`
		FindingHash        string   `json:"finding_hash"`
		SourceFile         string   `json:"source_file"`
		RepoName           string   `json:"repo_name"`
		ScanUUID           string   `json:"scan_uuid"`
		RecordUUIDs        []string `json:"http_record_uuids"`
		Hostname           string   `json:"hostname"`
		Status             string   `json:"status"`
		CreatedAt          string   `json:"created_at"`
	}
	// best-effort: render whatever fields decode; a malformed finding yields a sparse row.
	_ = json.Unmarshal(data, &f)

	name := f.ModuleShort
	if name == "" {
		name = f.ModuleName
	}

	title := name
	if f.URL != "" {
		title = name + " — " + truncateStr(f.URL, 80)
	}

	var descHTML template.HTML
	if f.Description != "" && md != nil {
		var buf bytes.Buffer
		if err := md.Convert([]byte(f.Description), &buf); err == nil {
			descHTML = template.HTML(buf.String())
		}
	}

	return ReportFinding{
		ID:                 f.ID,
		Title:              title,
		ModuleID:           f.ModuleID,
		ModuleName:         name,
		ModuleTitle:        f.ModuleName,
		Description:        f.Description,
		DescriptionHTML:    descHTML,
		Severity:           strings.ToLower(f.Severity),
		Confidence:         f.Confidence,
		CWE:                f.CWE,
		CVSSScore:          f.CVSSScore,
		Remediation:        f.Remediation,
		URL:                f.URL,
		MatchedAt:          f.MatchedAt,
		ExtractedResults:   f.ExtractedResults,
		Request:            f.Request,
		Response:           f.Response,
		AdditionalEvidence: f.AdditionalEvidence,
		Tags:               f.Tags,
		FoundAt:            f.FoundAt,
		FindingHash:        f.FindingHash,
		SourceFile:         f.SourceFile,
		RepoName:           f.RepoName,
		ScanUUID:           f.ScanUUID,
		RecordUUIDs:        f.RecordUUIDs,
		Hostname:           f.Hostname,
		Status:             f.Status,
		CreatedAt:          f.CreatedAt,
	}
}

// truncateStr caps s at maxLen bytes plus a "..." marker, never splitting a
// UTF-8 sequence (a split rune would make SARIF/JSON output invalid).
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return textutil.TruncateUTF8(s, maxLen) + "..."
}

// redactReportFinding scrubs credentials from a finding's shareable evidence:
// request/response headers and cookie values, sensitive query
// parameters in the request line and the URLs.
func redactReportFinding(rf *ReportFinding, extra map[string]struct{}) {
	rf.Request = redact.HTTPMessage(rf.Request, extra)
	rf.Response = redact.HTTPMessage(rf.Response, extra)
	if red := redact.URL(rf.URL); red != rf.URL {
		rf.Title = strings.Replace(rf.Title, truncateStr(rf.URL, 80), truncateStr(red, 80), 1)
		rf.URL = red
	}
	for i, m := range rf.MatchedAt {
		rf.MatchedAt[i] = redact.URL(m)
	}
	for i, e := range rf.AdditionalEvidence {
		rf.AdditionalEvidence[i] = redact.HTTPMessage(e, extra)
	}
}
