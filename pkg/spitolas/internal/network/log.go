package network

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorGreen   = "\033[32m"
	colorCyan    = "\033[36m"
	colorYellow  = "\033[33m"
	colorRed     = "\033[31m"
	colorMagenta = "\033[35m"
)

// methodColor returns color for HTTP method.
func methodColor(method string) string {
	switch method {
	case "GET":
		return colorGreen
	case "POST":
		return colorYellow
	case "PUT", "PATCH":
		return colorCyan
	case "DELETE":
		return colorRed
	default:
		return colorMagenta
	}
}

// contentTypeColor returns color for content type.
func contentTypeColor(ct string) string {
	switch {
	case strings.Contains(ct, "html"):
		return colorGreen
	case strings.Contains(ct, "json"):
		return colorYellow
	case strings.Contains(ct, "javascript"), strings.Contains(ct, "css"):
		return colorCyan
	case strings.Contains(ct, "image"), strings.Contains(ct, "font"):
		return colorMagenta
	default:
		return colorMagenta
	}
}

// statusColor returns color for HTTP status code.
func statusColor(status int) string {
	switch {
	case status >= 500:
		return colorRed
	case status >= 400:
		return colorYellow
	case status >= 300:
		return colorCyan
	default:
		return colorGreen
	}
}

// printLog prints HTTP request log to stderr with optional color.
// When phaseTag is non-empty, each line is prefixed with a dim phase label and pipe.
// Thread-safe: fmt.Fprintf to stderr is atomic for single lines (< PIPE_BUF).
func printLog(entry *TrafficEntry, noColor bool, phaseTag string) {
	var status string
	var sColor string

	if entry.Response == nil {
		status = "NO-RESPONSE"
		sColor = colorRed
	} else {
		status = strconv.Itoa(entry.Response.Status)
		sColor = statusColor(entry.Response.Status)
	}

	contentType := "-"
	if entry.Response != nil {
		if ct, ok := entry.Response.Headers["content-type"]; ok {
			contentType = parseContentType(ct)
		} else if ct, ok := entry.Response.Headers["Content-Type"]; ok {
			contentType = parseContentType(ct)
		}
	}

	method := entry.Request.Method
	mColor := methodColor(method)
	ctColor := contentTypeColor(contentType)

	// Build phase prefix (e.g. "› spider │ ")
	var prefix string
	var prefixVisibleLen int
	if phaseTag != "" {
		if noColor {
			prefix = terminal.SymbolChevron + " " + phaseTag + " " + terminal.SymbolPipe + " "
		} else {
			prefix = terminal.Muted(terminal.SymbolChevron+" "+phaseTag+" "+terminal.SymbolPipe) + " "
		}
		prefixVisibleLen = len(phaseTag) + 5 // chevron + space + tag + space + pipe + space
	}

	// Truncate URL so the full line fits within the terminal width.
	// Visible prefix: "phase│ [status] method contentType " (without ANSI codes).
	contentLen := len(status) + len(method) + len(contentType) + 6 // brackets + spaces
	totalPrefixLen := prefixVisibleLen + contentLen
	url := entry.Request.URL
	if termWidth := terminal.TerminalWidth(); termWidth > 0 && totalPrefixLen < termWidth {
		url = terminal.Truncate(url, termWidth-totalPrefixLen)
	}

	if noColor {
		fmt.Fprintf(os.Stderr, "%s[%s] %s %s %s\n", prefix, status, method, contentType, url)
	} else {
		fmt.Fprintf(os.Stderr, "%s%s[%s]%s %s%s%s %s%s%s %s\n",
			prefix,
			sColor, status, colorReset,
			mColor, method, colorReset,
			ctColor, contentType, colorReset,
			url)
	}
}

// parseContentType extracts the main content type (without charset and other params).
func parseContentType(ct string) string {
	if idx := strings.Index(ct, ";"); idx != -1 {
		return strings.TrimSpace(ct[:idx])
	}
	return ct
}
