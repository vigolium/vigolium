// Package wordlist provides runtime wordlist extraction from HTTP response bodies.
//
// It supports multiple content types (HTML, JSON, JavaScript, CSS, plain text)
// and uses a stream-based rune-by-rune tokenizer for memory-efficient processing.
//
// Key features:
//   - Content-type specific preprocessing (strip HTML tags, extract JSON strings, etc.)
//   - Configurable delimiter exceptions for compound words (e.g., admin-api)
//   - Partial combinations with MaxCombine setting
//   - Built-in keyword blacklists per content type
//   - Global deduplication
//   - URL decoding support
//
// Usage:
//
//	cfg := wordlist.DefaultConfig()
//	cfg.DelimExceptions = "-_"
//	cfg.MaxCombine = 2
//
//	extractor := wordlist.NewExtractor(cfg)
//	extractor.Extract(ctx, reader, "text/html", func(token *wordlist.Token) {
//	    fmt.Println(token.Value)
//	})
package wordlist
