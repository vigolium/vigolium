package wordlist

import (
	"context"
	"io"
)

// Config holds all wordlist extraction settings.
type Config struct {
	// MinLength filters tokens shorter than this (default: 3)
	MinLength int

	// MaxLength filters tokens longer than this (default: 64)
	MaxLength int

	// DelimExceptions are extra characters to include in tokens (e.g., "-_")
	// When included: "admin-api" outputs "admin", "api", AND "admin-api"
	DelimExceptions string

	// MaxCombine controls max segments to combine with delim (default: 2)
	// e.g., maxCombine=2: "admin-api-v2" → "admin-api", "api-v2"
	// e.g., maxCombine=3: also includes "admin-api-v2"
	MaxCombine int

	// AlphaNumOnly restricts output to [a-zA-Z0-9] only (default: true)
	AlphaNumOnly bool

	// AutoURLDecode automatically detects and decodes URL-encoded strings (default: true)
	AutoURLDecode bool

	// FilterKeywords enables built-in keyword filtering per content type (default: true)
	FilterKeywords bool
}

// DefaultConfig returns sensible defaults for wordlist extraction.
func DefaultConfig() *Config {
	return &Config{
		MinLength:       3,
		MaxLength:       64,
		DelimExceptions: "",
		MaxCombine:      2,
		AlphaNumOnly:    true,
		AutoURLDecode:   true,
		FilterKeywords:  true,
	}
}

// Token represents an extracted word/token.
type Token struct {
	// Value is the extracted token string
	Value string

	// Position is the byte offset in the source where this token was found
	Position int
}

// TokenCallback is invoked for each extracted token.
type TokenCallback func(token *Token)

// Preprocessor transforms content-type specific data into clean tokenizable text.
type Preprocessor interface {
	// Process transforms raw content into tokenizable text.
	// Returns an io.Reader for streaming processing.
	Process(ctx context.Context, reader io.Reader) (io.Reader, error)

	// ContentTypes returns the MIME types this preprocessor handles.
	ContentTypes() []string
}

// ContentType represents detected content type category.
type ContentType int

const (
	ContentTypeUnknown ContentType = iota
	ContentTypeHTML
	ContentTypeJSON
	ContentTypeJavaScript
	ContentTypeCSS
	ContentTypeText
	ContentTypeXML
)

// String returns the string representation of ContentType.
func (ct ContentType) String() string {
	switch ct {
	case ContentTypeHTML:
		return "html"
	case ContentTypeJSON:
		return "json"
	case ContentTypeJavaScript:
		return "javascript"
	case ContentTypeCSS:
		return "css"
	case ContentTypeText:
		return "text"
	case ContentTypeXML:
		return "xml"
	default:
		return "unknown"
	}
}
