package telegram

import (
	"github.com/vigolium/vigolium/pkg/output"
)

// Backend is the Telegram notification backend.
type Backend struct {
	client *Client
}

// NewBackend creates a new Telegram Backend.
// Configuration is loaded from environment variables if not provided via options.
func NewBackend(opts ...Option) (*Backend, error) {
	client, err := NewClient(opts...)
	if err != nil {
		return nil, err
	}
	return &Backend{client: client}, nil
}

// Send sends a scan result notification.
func (b *Backend) Send(result *output.ResultEvent) error {
	msg := FormatResult(result)

	return b.client.Send(msg)
}

// SendRaw sends a raw text message with markdown escaping.
func (b *Backend) SendRaw(msg string) error {
	return b.client.Send(EscapeMarkdown(msg))
}

// Close releases resources.
func (b *Backend) Close() {
	b.client.Close()
}
