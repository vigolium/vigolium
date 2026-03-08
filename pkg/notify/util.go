package notify

import (
	"fmt"
	"strings"
	"time"
)

// SanitizeFilename replaces invalid filename characters with underscores.
func SanitizeFilename(name string) string {
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_",
	)
	return replacer.Replace(name)
}

// GenerateFilename creates a filename for attachments.
// Format: {moduleID}_{host}_{timestamp}.{ext}
func GenerateFilename(moduleID, host, ext string) string {
	return fmt.Sprintf("%s_%s_%d.%s",
		SanitizeFilename(moduleID),
		SanitizeFilename(host),
		time.Now().UnixNano(),
		ext,
	)
}

// Truncate truncates a string to maxLen with ellipsis "...".
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// TruncateWithIndicator truncates a string and adds "[see attachment]".
func TruncateWithIndicator(s string, maxLen int) string {
	indicator := " [see attachment]"
	if len(s) <= maxLen {
		return s
	}
	cutLen := maxLen - len(indicator)
	if cutLen <= 0 {
		return indicator
	}
	return s[:cutLen] + indicator
}
