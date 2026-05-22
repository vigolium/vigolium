package output

import (
	"bytes"
	"encoding/json"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/public"
	"github.com/yuin/goldmark"
)

type ReportFinding struct {
	ID                 int
	Title              string
	ModuleID           string
	ModuleName         string
	Description        string
	DescriptionHTML    template.HTML
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
}

type ReportModule struct {
	ID       string
	Name     string
	Type     string
	Severity string
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
				ID       string `json:"id"`
				Name     string `json:"name"`
				Type     string `json:"type"`
				Severity string `json:"severity"`
				Enabled  bool   `json:"enabled"`
			}
			if err := json.Unmarshal(envelope.Data, &mod); err == nil && mod.Enabled {
				rd.Modules = append(rd.Modules, ReportModule{
					ID:       mod.ID,
					Name:     mod.Name,
					Type:     mod.Type,
					Severity: mod.Severity,
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
	if f.Description != "" {
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
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
