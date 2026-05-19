package curl

import (
	"strings"
)

// extractFromShellScript finds curl commands inside a bash script.
// It handles backslash-continuation lines and skips comments.
func extractFromShellScript(content string) []string {
	lines := strings.Split(content, "\n")
	joined := joinContinuationLines(lines)

	var commands []string
	for _, line := range joined {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// In shell scripts, curl must be at the start of the (trimmed) line
		// to avoid matching "echo curl" or similar
		if strings.HasPrefix(trimmed, "curl ") {
			commands = append(commands, trimmed)
		}
	}
	return commands
}

// extractFromMarkdown finds curl commands inside fenced code blocks in markdown.
func extractFromMarkdown(content string) []string {
	lines := strings.Split(content, "\n")
	var commands []string
	inCodeBlock := false

	var blockLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "```") {
			if inCodeBlock {
				// End of code block - process accumulated lines
				joined := joinContinuationLines(blockLines)
				for _, jl := range joined {
					cmd := extractCurlFromLine(strings.TrimSpace(jl))
					if cmd != "" {
						commands = append(commands, cmd)
					}
				}
				blockLines = nil
				inCodeBlock = false
			} else {
				// Start of code block
				inCodeBlock = true
				blockLines = nil
			}
			continue
		}

		if inCodeBlock {
			blockLines = append(blockLines, line)
		}
	}

	return commands
}

// joinContinuationLines joins lines ending with backslash into single lines.
func joinContinuationLines(lines []string) []string {
	var result []string
	var current strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t\r")

		if withoutSlash, ok := strings.CutSuffix(trimmed, "\\"); ok {
			// Remove trailing backslash and continue
			current.WriteString(withoutSlash)
			current.WriteByte(' ')
		} else {
			current.WriteString(line)
			result = append(result, current.String())
			current.Reset()
		}
	}

	// Don't forget any trailing content
	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}

// extractCurlFromLine extracts a curl command from a line.
// It finds the curl keyword and takes everything from there to end of line.
func extractCurlFromLine(line string) string {
	// Look for "curl " in the line
	idx := strings.Index(line, "curl ")
	if idx < 0 {
		// Also try "curl" at end of line (unlikely but possible)
		if strings.HasSuffix(line, "curl") {
			return ""
		}
		return ""
	}

	cmd := strings.TrimSpace(line[idx:])
	if cmd == "" || cmd == "curl" {
		return ""
	}

	return cmd
}
