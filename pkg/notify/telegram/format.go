package telegram

import (
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/output"
)

// FormatResult formats a ResultEvent for Telegram MarkdownV2.
func FormatResult(result *output.ResultEvent) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Module: *%s*\n",
		EscapeMarkdown(result.Info.Name))
	fmt.Fprintf(&sb, "Severity: *%s*\n",
		EscapeMarkdown(strings.TrimSpace(strings.ToTitle(result.Info.Severity.String()))))

	// Host. Formatting never touches the network (SAFE-11): it used to open a
	// TLS connection to the finding's host per notification, with no timeout,
	// outside the scan's proxy and rate limit, to list certificate names.
	fmt.Fprintf(&sb, "Host: *%s*\n", EscapeMarkdown(result.Host))

	fmt.Fprintf(&sb, "Date: *%s*\n",
		EscapeMarkdown(time.Now().Format("01/02/2006 15:04:05")))
	fmt.Fprintf(&sb, "Param Name: *%s*\n",
		EscapeMarkdown(strings.TrimSpace(result.FuzzingParameter)))
	if len(result.ExtractedResults) > 0 {
		fmt.Fprintf(&sb, "Extracted: *%s*\n",
			EscapeMarkdown(strings.TrimSpace(strings.Join(result.ExtractedResults, ", "))))
	}

	// Description
	if result.Info.Description != "" {
		fmt.Fprintf(&sb, "*Description*:\n%s\n",
			EscapeMarkdown(result.Info.Description))
	}

	// URL
	if result.URL != "" {
		sb.WriteString("*URL*:\n")
		fmt.Fprintf(&sb, "```\n%s\n```\n",
			EscapeMarkdown(strings.TrimSpace(result.URL)))
	}

	// Request
	if result.Request != "" {
		sb.WriteString("*Request*:\n")
		fmt.Fprintf(&sb, "```\n%s\n```\n",
			EscapeMarkdown(strings.TrimSpace(result.Request)))
	}

	return sb.String()
}
