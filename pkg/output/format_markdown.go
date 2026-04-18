package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func GenerateMarkdownReport(items []any, outputPath string, meta HTMLReportMeta) error {
	data := buildReportData(items, meta.Title, meta)

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	w := &strings.Builder{}

	writeMarkdownHeader(w, data)
	writeMarkdownTOC(w, data)
	writeMarkdownExecutiveSummary(w, data)
	writeMarkdownFindings(w, "Critical", data.CriticalFindings)
	writeMarkdownFindings(w, "High", data.HighFindings)
	writeMarkdownFindings(w, "Medium", data.MediumFindings)
	writeMarkdownFindings(w, "Low", data.LowFindings)
	writeMarkdownFindings(w, "Info", data.InfoFindings)

	_, err = f.WriteString(w.String())
	return err
}

func writeMarkdownHeader(w *strings.Builder, data ReportData) {
	fmt.Fprintf(w, "# %s\n\n", data.Title)
	fmt.Fprintf(w, "**Generated:** %s  \n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	if data.VigoliumVersion != "" {
		fmt.Fprintf(w, "**Vigolium Version:** %s  \n", data.VigoliumVersion)
	}
	if data.Target != "" {
		fmt.Fprintf(w, "**Target:** %s  \n", data.Target)
	}
	if data.ScanDuration != "" {
		fmt.Fprintf(w, "**Scan Duration:** %s  \n", data.ScanDuration)
	}
	w.WriteString("\n---\n\n")
}

func writeMarkdownTOC(w *strings.Builder, data ReportData) {
	w.WriteString("## Table of Contents\n\n")
	w.WriteString("- [Executive Summary](#executive-summary)\n")
	if data.CriticalCount > 0 {
		w.WriteString("- [Critical Findings](#critical-findings)\n")
	}
	if data.HighCount > 0 {
		w.WriteString("- [High Findings](#high-findings)\n")
	}
	if data.MediumCount > 0 {
		w.WriteString("- [Medium Findings](#medium-findings)\n")
	}
	if data.LowCount > 0 {
		w.WriteString("- [Low Findings](#low-findings)\n")
	}
	if data.InfoCount > 0 {
		w.WriteString("- [Info Findings](#info-findings)\n")
	}
	w.WriteString("\n")
}

func writeMarkdownExecutiveSummary(w *strings.Builder, data ReportData) {
	w.WriteString("## Executive Summary\n\n")
	fmt.Fprintf(w, "A total of **%d findings** were identified during the scan.\n\n", data.TotalFindings)

	w.WriteString("| Severity | Count |\n")
	w.WriteString("|----------|-------|\n")
	if data.CriticalCount > 0 {
		fmt.Fprintf(w, "| Critical | %d |\n", data.CriticalCount)
	}
	if data.HighCount > 0 {
		fmt.Fprintf(w, "| High | %d |\n", data.HighCount)
	}
	if data.MediumCount > 0 {
		fmt.Fprintf(w, "| Medium | %d |\n", data.MediumCount)
	}
	if data.LowCount > 0 {
		fmt.Fprintf(w, "| Low | %d |\n", data.LowCount)
	}
	if data.InfoCount > 0 {
		fmt.Fprintf(w, "| Info | %d |\n", data.InfoCount)
	}
	fmt.Fprintf(w, "| **Total** | **%d** |\n", data.TotalFindings)

	w.WriteString("\n")

	if data.TotalRequests > 0 {
		fmt.Fprintf(w, "**Total HTTP Requests:** %d  \n", data.TotalRequests)
	}
	if data.ActiveModules > 0 || data.PassiveModules > 0 {
		fmt.Fprintf(w, "**Modules:** %d active, %d passive  \n", data.ActiveModules, data.PassiveModules)
	}
	w.WriteString("\n")
}

func writeMarkdownFindings(w *strings.Builder, severity string, findings []ReportFinding) {
	if len(findings) == 0 {
		return
	}

	fmt.Fprintf(w, "## %s Findings\n\n", severity)

	for i, f := range findings {
		fmt.Fprintf(w, "### %d. %s\n\n", i+1, f.Title)

		if f.ModuleName != "" {
			fmt.Fprintf(w, "**Module:** %s", f.ModuleName)
			if f.ModuleID != "" {
				fmt.Fprintf(w, " (`%s`)", f.ModuleID)
			}
			w.WriteString("  \n")
		}
		fmt.Fprintf(w, "**Severity:** %s  \n", cases.Title(language.English).String(f.Severity))
		if f.Confidence != "" {
			fmt.Fprintf(w, "**Confidence:** %s  \n", f.Confidence)
		}
		if f.CWE != "" {
			fmt.Fprintf(w, "**CWE:** %s  \n", f.CWE)
		}
		if f.CVSSScore > 0 {
			fmt.Fprintf(w, "**CVSS:** %.1f  \n", f.CVSSScore)
		}
		if f.URL != "" {
			fmt.Fprintf(w, "**URL:** `%s`  \n", f.URL)
		}
		if f.SourceFile != "" {
			fmt.Fprintf(w, "**Source File:** `%s`  \n", f.SourceFile)
		}
		if f.RepoName != "" {
			fmt.Fprintf(w, "**Repository:** %s  \n", f.RepoName)
		}
		if f.FoundAt != "" {
			fmt.Fprintf(w, "**Found At:** %s  \n", f.FoundAt)
		}
		w.WriteString("\n")

		if f.Description != "" {
			fmt.Fprintf(w, "%s\n\n", f.Description)
		}

		if f.Remediation != "" {
			fmt.Fprintf(w, "**Remediation:** %s\n\n", f.Remediation)
		}

		if len(f.MatchedAt) > 0 {
			w.WriteString("**Matched At:**\n")
			for _, m := range f.MatchedAt {
				fmt.Fprintf(w, "- `%s`\n", m)
			}
			w.WriteString("\n")
		}

		if len(f.ExtractedResults) > 0 {
			w.WriteString("**Extracted Results:**\n")
			for _, r := range f.ExtractedResults {
				fmt.Fprintf(w, "- `%s`\n", r)
			}
			w.WriteString("\n")
		}

		if len(f.AdditionalEvidence) > 0 {
			w.WriteString("**Additional Evidence:**\n")
			for _, e := range f.AdditionalEvidence {
				fmt.Fprintf(w, "- %s\n", e)
			}
			w.WriteString("\n")
		}

		if f.Request != "" {
			w.WriteString("<details>\n<summary>HTTP Request</summary>\n\n```http\n")
			w.WriteString(f.Request)
			w.WriteString("\n```\n\n</details>\n\n")
		}

		if f.Response != "" {
			w.WriteString("<details>\n<summary>HTTP Response</summary>\n\n```http\n")
			w.WriteString(truncateStr(f.Response, 2000))
			w.WriteString("\n```\n\n</details>\n\n")
		}

		if len(f.Tags) > 0 {
			fmt.Fprintf(w, "**Tags:** %s\n\n", strings.Join(f.Tags, ", "))
		}

		w.WriteString("---\n\n")
	}
}

