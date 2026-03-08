package payload

import (
	"context"
	"hash/fnv"
	"io"
)

// DefaultExtensionVariants contains 43 file extension variants for backup/temp file testing.
// Includes Burp Suite defaults (bow.java) plus high-value pentester additions.
var DefaultExtensionVariants = []string{
	// Vim swap files - often contain full source code
	"swp", "swo",
	// Distribution/template files - often have credentials
	"dist", "sample", "example",
	// Burp Suite defaults (bow.java)
	"~", "~1", "$$$", "1", "bac", "backup", "bak", "conf", "cs", "csproj",
	"gz", "inc", "ini", "java", "log", "old", "sav", "tar", "tmp",
	"zip", "~bk", "0", "BAC", "BACKUP", "BAK", "OLD", "INC", "lst",
	"orig", "ORIG", "save", "temp", "TMP", "-OLD", "-old", "vbproj", "vb",
}

// ExtensionProvider generates extension variant payloads for backup file testing.
// These are typically appended to discovered filenames (e.g., index.php.bak).
//
// NOT thread-safe. Thread-safety is provided by PayloadDispatcher which serializes
// all calls to Next(). This provider should only be accessed through a dispatcher.
type ExtensionProvider struct {
	variants [][]byte
	index    int
}

// NewExtensionProvider creates a provider with default extension variants.
func NewExtensionProvider() *ExtensionProvider {
	return NewExtensionProviderWithVariants(DefaultExtensionVariants)
}

// NewExtensionProviderWithVariants creates a provider with custom variants.
func NewExtensionProviderWithVariants(variants []string) *ExtensionProvider {
	byteVariants := make([][]byte, len(variants))
	for i, v := range variants {
		byteVariants[i] = []byte(v)
	}
	return &ExtensionProvider{
		variants: byteVariants,
		index:    0,
	}
}

// Next returns the next extension variant or io.EOF when exhausted.
func (e *ExtensionProvider) Next(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if e.index >= len(e.variants) {
		return nil, io.EOF
	}

	variant := e.variants[e.index]
	e.index++
	return variant, nil
}

// Count returns the total number of variants.
func (e *ExtensionProvider) Count() int {
	return len(e.variants)
}

// Name returns a descriptive name for this provider.
func (e *ExtensionProvider) Name() string {
	return "extension"
}

// Close releases any resources held by the provider.
func (e *ExtensionProvider) Close() error {
	return nil
}

// HashContent returns a FNV-1a 64-bit hash of the extension variants.
func (e *ExtensionProvider) HashContent() uint64 {
	h := fnv.New64a()
	for _, variant := range e.variants {
		h.Write(variant)
		h.Write([]byte{0}) // Separator
	}
	return h.Sum64()
}
