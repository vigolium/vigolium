package wordlist

import (
	"context"
	"io"
)

// TextPreprocessor is the default passthrough preprocessor for plain text.
type TextPreprocessor struct{}

// Process passes through the content unchanged.
func (p *TextPreprocessor) Process(_ context.Context, reader io.Reader) (io.Reader, error) {
	return reader, nil
}

// ContentTypes returns the MIME types handled by this preprocessor.
func (p *TextPreprocessor) ContentTypes() []string {
	return []string{
		"text/plain",
		"*/*", // Default fallback
	}
}
