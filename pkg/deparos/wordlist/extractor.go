package wordlist

import (
	"bytes"
	"context"
	"io"
)

// Extractor coordinates preprocessing and tokenization for wordlist extraction.
// Note: Deduplication is handled by the callback consumer (e.g., ObservedProvider with LRU).
type Extractor struct {
	cfg       *Config
	tokenizer *Tokenizer
	registry  *PreprocessorRegistry
}

// NewExtractor creates a new Extractor with the given config.
func NewExtractor(cfg *Config) *Extractor {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &Extractor{
		cfg:       cfg,
		tokenizer: NewTokenizer(cfg),
		registry:  NewPreprocessorRegistry(),
	}
}

// Extract processes the content and calls callback for each extracted token.
// This method is thread-safe and can be called concurrently.
// Deduplication is NOT performed here - the callback consumer handles it.
func (e *Extractor) Extract(ctx context.Context, reader io.Reader, contentType string, callback TokenCallback) error {
	// Check if we should process this content type
	if !ShouldProcess(contentType) {
		return nil
	}

	// Read all data for detection and preprocessing
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}

	// Detect content type if not provided or unknown
	var ct ContentType
	if contentType == "" {
		ct = DetectContentType(data)
	} else {
		ct = e.registry.GetContentType(contentType)
	}

	// Get appropriate preprocessor
	preprocessor := e.registry.Get(contentType)

	// Preprocess the content
	processed, err := preprocessor.Process(ctx, bytes.NewReader(data))
	if err != nil {
		return err
	}

	// Local seen map for this extraction (tokenizer uses this for consecutive dedup within single response)
	localSeen := make(map[string]struct{})

	// Tokenize and call callback directly - global dedup is handled by ObservedProvider
	return e.tokenizer.Tokenize(ctx, processed, ct, localSeen, callback)
}

// ExtractBytes is a convenience method that takes a byte slice instead of a reader.
func (e *Extractor) ExtractBytes(ctx context.Context, data []byte, contentType string, callback TokenCallback) error {
	return e.Extract(ctx, bytes.NewReader(data), contentType, callback)
}

// Config returns the extractor's configuration.
func (e *Extractor) Config() *Config {
	return e.cfg
}
