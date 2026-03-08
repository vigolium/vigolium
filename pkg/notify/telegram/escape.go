package telegram

import (
	"strings"
)

// markdownV2EscapeChars contains characters that need escaping in Telegram MarkdownV2.
var markdownV2EscapeChars = "_\\*[]()~`>#+-=|{}.!"

// EscapeMarkdown escapes special characters for Telegram MarkdownV2 syntax.
func EscapeMarkdown(s string) string {
	var result []rune
	for _, r := range s {
		if strings.ContainsRune(markdownV2EscapeChars, r) {
			result = append(result, '\\')
		}
		result = append(result, r)
	}
	return string(result)
}

// splitMessage splits a message into chunks that fit within maxBytes.
// It tries to split at newline boundaries when possible.
func splitMessage(message string, maxBytes int) []string {
	if len([]byte(message)) <= maxBytes {
		return []string{message}
	}

	var chunks []string
	var currentChunk strings.Builder
	var currentBytes int

	lines := strings.Split(message, "\n")

	for _, line := range lines {
		lineBytes := len([]byte(line))
		newlineBytes := 1

		if currentBytes+lineBytes+newlineBytes <= maxBytes {
			if currentChunk.Len() > 0 {
				currentChunk.WriteString("\n")
			}
			currentChunk.WriteString(line)
			currentBytes += lineBytes + newlineBytes
		} else {
			if lineBytes > maxBytes {
				// Line itself is too long, truncate it
				if currentChunk.Len() > 0 {
					chunks = append(chunks, currentChunk.String())
					currentChunk.Reset()
					currentBytes = 0
				}
				truncatedLine := truncateLine(line, maxBytes)
				chunks = append(chunks, truncatedLine)
			} else {
				// Save current chunk and start new one
				if currentChunk.Len() > 0 {
					chunks = append(chunks, currentChunk.String())
				}
				currentChunk.Reset()
				currentChunk.WriteString(line)
				currentBytes = lineBytes
			}
		}
	}

	if currentChunk.Len() > 0 {
		chunks = append(chunks, currentChunk.String())
	}

	return chunks
}

// truncateLine truncates a line to fit within maxBytes, adding ellipsis.
func truncateLine(line string, maxBytes int) string {
	const ellipsis = "..."

	if len([]byte(line)) <= maxBytes {
		return line
	}

	truncatedBytes := maxBytes - len(ellipsis)
	if truncatedBytes < 0 {
		truncatedBytes = 0
	}

	// Truncate to byte boundary
	truncated := string([]byte(line)[:truncatedBytes])
	return truncated + ellipsis
}
