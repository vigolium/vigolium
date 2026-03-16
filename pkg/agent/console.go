package agent

import (
	"fmt"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// printPhaseLine prints a console line in the standard scanning output style:
//
//	❯ source-analysis │ message key=value
//
// The message text is printed in bold, and key=value pairs are colorized
// (key in muted, value in cyan).
func printPhaseLine(phaseTag, message string) {
	prefix := terminal.Muted(terminal.SymbolChevron+" "+phaseTag+" "+terminal.SymbolPipe) + " "
	fmt.Fprintf(os.Stderr, "%s%s\n", prefix, colorizeMessage(message))
}

// colorizeMessage applies color to a phase-line message body.
// It splits the message into a leading text portion and trailing key=value
// pairs separated by double-space ("  "). The text is bolded, and each
// key=value token is colorized (key muted, value cyan).
func colorizeMessage(msg string) string {
	// Messages use double-space to separate the description from KV pairs,
	// e.g. "ingested HTTP records  count=37".
	// Some messages are purely descriptive with no KV section.
	parts := strings.SplitN(msg, "  ", 2)
	desc := parts[0]

	// Colorize the descriptive portion.
	colored := terminal.Bold(desc)

	if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
		return colored
	}

	// Colorize key=value tokens in the KV section.
	kvSection := parts[1]
	tokens := strings.Fields(kvSection)
	var coloredTokens []string
	for _, tok := range tokens {
		if eqIdx := strings.Index(tok, "="); eqIdx > 0 {
			key := tok[:eqIdx]
			val := tok[eqIdx+1:]
			coloredTokens = append(coloredTokens, terminal.Muted(key+"=")+terminal.Cyan(val))
		} else {
			// Parenthesized status summaries or other non-KV tokens
			coloredTokens = append(coloredTokens, terminal.Muted(tok))
		}
	}

	return colored + "  " + strings.Join(coloredTokens, " ")
}

// formatStatusSummary returns a colorized parenthesized summary of HTTP status
// code counts, e.g. "(2xx: 35, 4xx: 12, no-response: 3)".
func formatStatusSummary(s2xx, s3xx, s4xx, s5xx, noResp int64) string {
	var parts []string
	if s2xx > 0 {
		parts = append(parts, terminal.Green(fmt.Sprintf("2xx: %d", s2xx)))
	}
	if s3xx > 0 {
		parts = append(parts, terminal.Cyan(fmt.Sprintf("3xx: %d", s3xx)))
	}
	if s4xx > 0 {
		parts = append(parts, terminal.Yellow(fmt.Sprintf("4xx: %d", s4xx)))
	}
	if s5xx > 0 {
		parts = append(parts, terminal.Red(fmt.Sprintf("5xx: %d", s5xx)))
	}
	if noResp > 0 {
		parts = append(parts, terminal.Muted(fmt.Sprintf("no-response: %d", noResp)))
	}
	if len(parts) == 0 {
		return ""
	}
	return terminal.Muted("(") + strings.Join(parts, terminal.Muted(", ")) + terminal.Muted(")")
}
