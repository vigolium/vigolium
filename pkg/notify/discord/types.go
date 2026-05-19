package discord

import "strings"

// Discord limits
const (
	MaxFieldValue     = 1024
	MaxDescription    = 4096
	MaxEmbedTotal     = 6000
	MaxMessageContent = 2000
	MaxRequestPreview = 900 // Leave room for code block markers
)

// WebhookMessage represents a Discord webhook message.
type WebhookMessage struct {
	Content string  `json:"content,omitempty"`
	Embeds  []Embed `json:"embeds,omitempty"`
}

// Embed represents a Discord embed.
type Embed struct {
	Title       string  `json:"title,omitempty"`
	Description string  `json:"description,omitempty"`
	Color       int     `json:"color,omitempty"`
	Fields      []Field `json:"fields,omitempty"`
	Timestamp   string  `json:"timestamp,omitempty"`
	Footer      *Footer `json:"footer,omitempty"`
}

// Field represents a Discord embed field.
type Field struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// Footer represents a Discord embed footer.
type Footer struct {
	Text string `json:"text"`
}

// Severity colors for Discord embeds.
var severityColors = map[string]int{
	"critical": 10038562, // Dark red
	"high":     15158332, // Red
	"medium":   16753920, // Orange
	"low":      16776960, // Yellow
	"info":     3447003,  // Blue
}

// GetSeverityColor returns the Discord color for a severity level.
func GetSeverityColor(severity string) int {
	if color, ok := severityColors[strings.ToLower(severity)]; ok {
		return color
	}
	return 9807270 // Gray default
}
