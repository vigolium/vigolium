package notify

import "github.com/vigolium/vigolium/pkg/output"

// Backend is the interface for notification backends.
// Each backend handles its own formatting, escaping, length limits, and file uploads.
type Backend interface {
	// Send sends a scan result notification.
	Send(result *output.ResultEvent) error

	// SendRaw sends a raw text message (for panics, errors).
	SendRaw(msg string) error

	// Close releases any resources held by the backend.
	Close()
}
