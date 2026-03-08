package discord

import "strings"

// EscapeMarkdown escapes special characters for Discord markdown.
func EscapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\", // Escape backslashes first
		"*", "\\*",
		"_", "\\_",
		"~", "\\~",
		"|", "\\|",
		"`", "\\`",
		"@", "\\@",
		"#", "\\#",
	)
	return replacer.Replace(s)
}
