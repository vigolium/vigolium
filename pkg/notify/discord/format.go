package discord

import (
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/output"
)

// Overflow represents content that exceeds Discord limits and should be sent as file.
type Overflow struct {
	Filename string
	Content  []byte
}

// FormatEmbed formats a ResultEvent as a Discord embed.
// Returns the embed message and optional overflow file if content exceeds limits.
func FormatEmbed(result *output.ResultEvent) (*WebhookMessage, *Overflow) {
	color := GetSeverityColor(result.Info.Severity.String())

	fields := []Field{
		{
			Name:   "Module",
			Value:  EscapeMarkdown(result.Info.Name),
			Inline: true,
		},
		{
			Name:   "Severity",
			Value:  EscapeMarkdown(strings.ToUpper(result.Info.Severity.String())),
			Inline: true,
		},
		{
			Name:   "Host",
			Value:  EscapeMarkdown(result.Host),
			Inline: true,
		},
		{
			Name:   "Date",
			Value:  time.Now().Format("01/02/2006 15:04:05"),
			Inline: true,
		},
	}

	// Add parameter if present
	if result.FuzzingParameter != "" {
		fields = append(fields, Field{
			Name:   "Parameter",
			Value:  truncateField(EscapeMarkdown(result.FuzzingParameter)),
			Inline: true,
		})
	}

	// Add URL
	if result.URL != "" {
		urlValue := result.URL
		if len(urlValue) > 500 {
			urlValue = urlValue[:500] + "..."
		}
		fields = append(fields, Field{
			Name:   "URL",
			Value:  EscapeMarkdown(urlValue),
			Inline: false,
		})
	}

	// Handle request field - may need overflow
	var overflow *Overflow
	if result.Request != "" {
		if len(result.Request) > MaxRequestPreview {
			// Truncate for embed, full content as file
			preview := result.Request[:MaxRequestPreview] + "\n[...truncated, see attachment]"
			fields = append(fields, Field{
				Name:   "Request",
				Value:  fmt.Sprintf("```http\n%s\n```", preview),
				Inline: false,
			})
			overflow = &Overflow{
				Filename: notify.GenerateFilename(result.ModuleID, result.Host, "txt"),
				Content:  []byte(result.Request),
			}
		} else {
			fields = append(fields, Field{
				Name:   "Request",
				Value:  fmt.Sprintf("```http\n%s\n```", result.Request),
				Inline: false,
			})
		}
	}

	embed := Embed{
		Title:     fmt.Sprintf("Vulnerability: %s", result.Info.Name),
		Color:     color,
		Fields:    fields,
		Timestamp: time.Now().Format(time.RFC3339),
		Footer:    &Footer{Text: "Vigolium Scanner"},
	}

	// Add description if present
	if result.Info.Description != "" {
		desc := result.Info.Description
		if len(desc) > MaxDescription {
			desc = desc[:MaxDescription-3] + "..."
		}
		embed.Description = EscapeMarkdown(desc)
	}

	return &WebhookMessage{Embeds: []Embed{embed}}, overflow
}

// truncateField truncates a field value to Discord's max field value length.
func truncateField(s string) string {
	if len(s) <= MaxFieldValue {
		return s
	}
	return s[:MaxFieldValue-3] + "..."
}
