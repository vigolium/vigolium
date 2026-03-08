package wordlist

import (
	"bufio"
	"context"
	"io"
	"net/url"
	"strings"
)

// Tokenizer extracts words from text using streaming rune-by-rune processing.
type Tokenizer struct {
	cfg *Config

	// delimExceptionSet for O(1) lookup
	delimExceptionSet map[rune]struct{}

	// keywordFilter for content-type specific filtering
	keywordFilter *KeywordFilter
}

// NewTokenizer creates a new Tokenizer with the given config.
func NewTokenizer(cfg *Config) *Tokenizer {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Build delimiter exception set
	delimSet := make(map[rune]struct{})
	for _, r := range cfg.DelimExceptions {
		delimSet[r] = struct{}{}
	}

	return &Tokenizer{
		cfg:               cfg,
		delimExceptionSet: delimSet,
		keywordFilter:     NewKeywordFilter(),
	}
}

// Tokenize processes the reader and calls callback for each extracted token.
// The contentType is used for keyword filtering.
// seen is used for global deduplication across multiple calls.
func (t *Tokenizer) Tokenize(ctx context.Context, reader io.Reader, contentType ContentType, seen map[string]struct{}, callback TokenCallback) error {
	br := bufio.NewReader(reader)

	var currentSegment []rune  // Current word being built
	var segments []segmentInfo // All segments in current delim-separated sequence
	var currentDelim rune      // The delimiter between segments (for joining)
	position := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		r, size, err := br.ReadRune()
		if err == io.EOF {
			// Flush final segment and combinations
			if len(currentSegment) > 0 {
				segments = append(segments, segmentInfo{
					value:    string(currentSegment),
					position: position - len(currentSegment),
				})
				t.emitSegment(currentSegment, position-len(currentSegment), contentType, seen, callback)
			}
			if len(segments) > 1 {
				t.emitCombinations(segments, currentDelim, contentType, seen, callback)
			}
			return nil
		}
		if err != nil {
			return err
		}

		if t.isTokenChar(r) {
			currentSegment = append(currentSegment, r)
		} else if t.isDelimException(r) && len(currentSegment) > 0 {
			// Delim-exception: store current segment, continue building
			segments = append(segments, segmentInfo{
				value:    string(currentSegment),
				position: position - len(currentSegment),
			})
			t.emitSegment(currentSegment, position-len(currentSegment), contentType, seen, callback)
			currentSegment = nil
			currentDelim = r
		} else {
			// Token boundary - flush everything
			if len(currentSegment) > 0 {
				segments = append(segments, segmentInfo{
					value:    string(currentSegment),
					position: position - len(currentSegment),
				})
				t.emitSegment(currentSegment, position-len(currentSegment), contentType, seen, callback)
			}

			// Emit combinations if we have multiple segments
			if len(segments) > 1 {
				t.emitCombinations(segments, currentDelim, contentType, seen, callback)
			}

			// Reset
			currentSegment = nil
			segments = nil
			currentDelim = 0
		}

		position += size
	}
}

type segmentInfo struct {
	value    string
	position int
}

// isTokenChar returns true if the rune should be part of a token.
func (t *Tokenizer) isTokenChar(r rune) bool {
	if t.cfg.AlphaNumOnly {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
	}
	// Allow letters and digits from all unicode categories
	return isLetter(r) || isDigit(r)
}

// isLetter checks if rune is a letter (simplified).
func isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= 0x00C0 && r <= 0x00FF) || // Latin Extended
		(r >= 0x0100 && r <= 0x017F) // Latin Extended-A
}

// isDigit checks if rune is a digit.
func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

// isDelimException returns true if the rune is in the delimiter exception set.
func (t *Tokenizer) isDelimException(r rune) bool {
	_, ok := t.delimExceptionSet[r]
	return ok
}

// emitSegment emits a single segment (individual word).
func (t *Tokenizer) emitSegment(segment []rune, pos int, contentType ContentType, seen map[string]struct{}, callback TokenCallback) {
	if len(segment) < t.cfg.MinLength || len(segment) > t.cfg.MaxLength {
		return
	}

	value := string(segment)

	// URL decode if needed
	if t.cfg.AutoURLDecode && strings.Contains(value, "%") {
		if decoded, err := url.PathUnescape(value); err == nil && decoded != value {
			value = decoded
		}
	}

	// Check length again after decoding
	if len(value) < t.cfg.MinLength || len(value) > t.cfg.MaxLength {
		return
	}

	// Global dedup
	if _, exists := seen[value]; exists {
		return
	}

	// Keyword filter
	if t.cfg.FilterKeywords && t.keywordFilter.IsKeyword(value, contentType) {
		return
	}

	seen[value] = struct{}{}
	callback(&Token{Value: value, Position: pos})
}

// emitCombinations emits partial combinations of segments.
func (t *Tokenizer) emitCombinations(segments []segmentInfo, delim rune, contentType ContentType, seen map[string]struct{}, callback TokenCallback) {
	if t.cfg.MaxCombine < 2 {
		return
	}

	delimStr := string(delim)
	maxWindow := t.cfg.MaxCombine
	if maxWindow > len(segments) {
		maxWindow = len(segments)
	}

	// Generate sliding window combinations
	for windowSize := 2; windowSize <= maxWindow; windowSize++ {
		for start := 0; start <= len(segments)-windowSize; start++ {
			var parts []string
			for i := start; i < start+windowSize; i++ {
				parts = append(parts, segments[i].value)
			}
			combined := strings.Join(parts, delimStr)

			// Check length
			if len(combined) < t.cfg.MinLength || len(combined) > t.cfg.MaxLength {
				continue
			}

			// Global dedup
			if _, exists := seen[combined]; exists {
				continue
			}

			// Keyword filter (less strict for combined - only filter if ALL parts are keywords)
			if t.cfg.FilterKeywords {
				allKeywords := true
				for _, part := range parts {
					if !t.keywordFilter.IsKeyword(part, contentType) {
						allKeywords = false
						break
					}
				}
				if allKeywords {
					continue
				}
			}

			seen[combined] = struct{}{}
			callback(&Token{Value: combined, Position: segments[start].position})
		}
	}
}
