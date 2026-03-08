package discord

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/output"
)

// Backend is the Discord webhook notification backend.
type Backend struct {
	webhookURL string
	httpClient *http.Client
}

// NewBackend creates a new Discord Backend.
func NewBackend(webhookURL string) (*Backend, error) {
	if strings.TrimSpace(webhookURL) == "" {
		return nil, fmt.Errorf("discord webhook URL cannot be empty")
	}

	if !strings.Contains(webhookURL, "discord.com/api/webhooks/") {
		return nil, fmt.Errorf("invalid Discord webhook URL format")
	}

	return &Backend{
		webhookURL: webhookURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Send sends a scan result notification.
func (b *Backend) Send(result *output.ResultEvent) error {
	embed, overflow := FormatEmbed(result)

	if overflow != nil {
		return b.sendWithFile(embed, overflow.Filename, overflow.Content)
	}

	return b.send(embed)
}

// SendRaw sends a raw text message.
func (b *Backend) SendRaw(msg string) error {
	if len(msg) > MaxMessageContent {
		return b.sendFile("message.txt", []byte(msg))
	}
	return b.sendContent(EscapeMarkdown(msg))
}

// Close releases resources (no-op for webhook).
func (b *Backend) Close() {}
