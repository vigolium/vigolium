package output

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// maxFileSuffixWidth caps the extracted-results/evidence suffix when output is
// redirected to a file or pipe, where terminal-width truncation is skipped.
const maxFileSuffixWidth = 500

// oneLineEscaper renders embedded control characters as their literal
// backslash-escape sequences. A CRLF pair collapses to a single \n so
// Windows-style line breaks don't render as the noisier \r\n.
var oneLineEscaper = strings.NewReplacer(
	"\r\n", `\n`,
	"\r", `\r`,
	"\n", `\n`,
	"\t", `\t`,
)

// EscapeOneLine renders embedded control characters (newlines, carriage
// returns, tabs) as their literal backslash-escape sequences so a finding's
// extracted value always prints as a single console line — while preserving
// the visual cue that the value spanned multiple lines (e.g. a JS snippet),
// rather than collapsing the structure away into spaces. Values without such
// characters pass through untouched.
func EscapeOneLine(s string) string {
	if !strings.ContainsAny(s, "\r\n\t") {
		return s
	}
	return oneLineEscaper.Replace(s)
}

// formatScreen formats the output for showing on screen.
// Format: [template-id] [type] [severity] matched-at [extracted-results]
func (w *StandardWriter) formatScreen(output *ResultEvent) []byte {
	builder := &bytes.Buffer{}

	// Phase prefix (e.g. "› scan │ ")
	var phasePrefixLen int
	if w.PhaseTag != "" {
		builder.WriteString(terminal.Muted(terminal.SymbolChevron + " " + w.PhaseTag + " " + terminal.SymbolPipe))
		builder.WriteRune(' ')
		phasePrefixLen = len(w.PhaseTag) + 5 // chevron + space + tag + space + pipe + space
	}

	// [type] [module-name]
	// Suppress [type] when it duplicates the outer phase tag (e.g. PhaseTag
	// "known-issue-scan" + ModuleType "known-issue-scan"). The phase wrapper
	// already conveys the same info, so rendering both is just noise.
	var moduleType string
	if output.ModuleType != "" && !strings.EqualFold(output.ModuleType, w.PhaseTag) {
		moduleType = output.ModuleType
	}
	moduleName := output.ModuleID
	if moduleType != "" {
		builder.WriteRune('[')
		builder.WriteString(moduleTypeColor(moduleType))
		builder.WriteString("] ")
	}
	if moduleName != "" {
		builder.WriteRune('[')
		builder.WriteString(moduleName)
		builder.WriteString("] ")
	}

	// [severity] with color
	builder.WriteRune('[')
	builder.WriteString(severityColor(output.Info.Severity))
	builder.WriteString("] ")

	// Calculate visible prefix length for truncation:
	// [type] [moduleName] [symbol severity] = content + brackets/spaces
	// symbol(1) + space(1) + severity + brackets(4-6) + spaces(2-3)
	prefixLen := phasePrefixLen + len(moduleType) + len(moduleName) + len(output.Info.Severity.String()) + 11
	if moduleType == "" {
		prefixLen -= 3 // no "[" + "] " for module type
	}
	if moduleName == "" {
		prefixLen -= 3 // no "[" + "] " for module name
	}
	// matched-at (URL)
	urlStr := MatchedURL(output)

	// Prepend HTTP method when available
	if output.Request != "" {
		if method, err := httpmsg.GetMethod([]byte(output.Request)); err == nil && method != "" {
			urlStr = method + " " + urlStr
			prefixLen += len(method) + 1
		}
	}

	termWidth := terminal.TerminalWidth()
	remaining := termWidth - prefixLen

	// Build suffix parts (extracted results, fuzzing parameter) first to account for their width
	var suffix string
	if len(output.ExtractedResults) > 0 {
		suffix = " [" + EscapeOneLine(strings.Join(output.ExtractedResults, ",")) + "]"
	}
	if output.IsFuzzingResult && output.FuzzingParameter != "" {
		suffix += " [" + output.FuzzingParameter + "]"
	}
	// Hint that the finding carries extra comparison evidence (baseline,
	// confirmation rounds). The console is the only output that doesn't show the
	// pairs inline; the other formats (jsonl/html/markdown/UI) render them in full.
	if n := len(output.AdditionalEvidence); n > 0 {
		suffix += " (+" + strconv.Itoa(n) + " evidence pairs)"
	}

	// Truncate URL + suffix to fit terminal width — but only when writing to an
	// interactive terminal. When stdout is redirected to a file or pipe (e.g. the
	// per-target .console.log captured by `-P` parallel scans), term.GetSize fails
	// and TerminalWidth falls back to 150, which would clip URLs/payloads mid-token
	// with an ellipsis. File/pipe consumers want the full URL, so the URL is never
	// truncated there — only the evidence suffix is capped (it is unbounded:
	// per-match snippet extractors can emit thousands of chars per finding; the
	// full data is still in jsonl/html/DB).
	if terminal.IsTerminal() && remaining > 20 {
		combined := urlStr + suffix
		if len(combined) > remaining {
			if len(suffix) >= remaining {
				// Suffix alone exceeds available space; drop it and truncate URL only
				suffix = ""
				urlStr = terminal.Truncate(urlStr, remaining)
			} else {
				urlStr = terminal.Truncate(urlStr, remaining-len(suffix))
			}
		}
	} else if !terminal.IsTerminal() {
		suffix = terminal.Truncate(suffix, maxFileSuffixWidth)
	}

	builder.WriteString(urlStr)
	if suffix != "" {
		builder.WriteString(terminal.Gray(suffix))
	}

	return builder.Bytes()
}

// severityColor returns ANSI color coded severity string with symbol
func severityColor(s severity.Severity) string {
	symbol := getSeveritySymbol(s)
	coloredText := ""

	switch s {
	case severity.Critical:
		coloredText = terminal.BoldMagenta(s.String())
	case severity.High:
		coloredText = terminal.BoldRed(s.String())
	case severity.Medium:
		coloredText = terminal.BoldYellow(s.String())
	case severity.Low:
		coloredText = terminal.BoldGreen(s.String())
	case severity.Suspect:
		coloredText = terminal.BoldCyan(s.String())
	case severity.Info:
		coloredText = terminal.BoldBlue(s.String())
	default:
		return s.String()
	}

	return symbol + " " + coloredText
}

// moduleTypeColor returns the module type string with appropriate color.
func moduleTypeColor(moduleType string) string {
	switch moduleType {
	case "active":
		return terminal.BoldGreen(moduleType)
	case "passive":
		return terminal.BoldBlue(moduleType)
	default:
		return moduleType
	}
}

// getSeveritySymbol returns the symbol for a given severity level
func getSeveritySymbol(s severity.Severity) string {
	switch s {
	case severity.Critical:
		return terminal.CriticalSymbol()
	case severity.High:
		return terminal.HighSymbol()
	case severity.Medium:
		return terminal.MediumSymbol()
	case severity.Low:
		return terminal.LowSymbol()
	case severity.Suspect:
		return terminal.SuspectSymbol()
	case severity.Info:
		return terminal.InfoSeveritySymbol()
	default:
		return ""
	}
}
