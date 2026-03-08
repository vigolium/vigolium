package input_behavior_probe

import (
	"regexp"
	"strings"
)

var tagPattern = regexp.MustCompile(`(?i)<[a-z]+`)

// ExtractTags extracts all opening HTML tags from response body.
// Returns concatenated string of tags: "<div<script<a..."
func ExtractTags(body string) string {
	matches := tagPattern.FindAllString(body, -1)
	if len(matches) == 0 {
		return ""
	}
	var result strings.Builder
	for _, m := range matches {
		result.WriteString(strings.ToLower(m))
	}
	return result.String()
}
