package xss_light_scanner

import (
	"strings"
)

// TransformAnalyzer detects how input characters were transformed in response
type TransformAnalyzer struct{}

// NewTransformAnalyzer creates a new TransformAnalyzer
func NewTransformAnalyzer() *TransformAnalyzer {
	return &TransformAnalyzer{}
}

// AnalyzeTransforms detects transforms for all breakout chars in matched bytes
func (ta *TransformAnalyzer) AnalyzeTransforms(
	matchedBytes []byte,
	payload *CanaryPayload,
	context ReflectionContext,
	offset int,
) *EscapeAnalysis {
	analysis := NewEscapeAnalysis(context, offset)
	analysis.PayloadSent = payload.FullPayload
	analysis.ResponseSnippet = string(matchedBytes)

	// Analyze breakout chars
	for _, ch := range BreakoutChars {
		transform := ta.detectCharTransform(matchedBytes, payload, ch)
		if transform != nil {
			analysis.SetTransform(string(ch), transform)
		}
	}

	return analysis
}

// AnalyzeSequenceTransforms detects transforms for multi-char sequences (e.g., \')
func (ta *TransformAnalyzer) AnalyzeSequenceTransforms(
	matchedBytes []byte,
	payload *CanaryPayload,
	sequences []string,
) map[string]*CharTransform {
	transforms := make(map[string]*CharTransform)

	for _, seq := range sequences {
		transform := ta.detectSequenceTransform(matchedBytes, payload, seq)
		if transform != nil {
			transforms[seq] = transform
		}
	}

	return transforms
}

// detectCharTransform detects how a single character was transformed
func (ta *TransformAnalyzer) detectCharTransform(
	matchedBytes []byte,
	payload *CanaryPayload,
	ch byte,
) *CharTransform {
	segBefore := payload.GetSegmentBefore(ch)
	segAfter := payload.GetSegmentAfter(ch)

	if segBefore == "" || segAfter == "" {
		return nil
	}

	matchStr := string(matchedBytes)
	inputSeq := string(ch)

	// Pattern 1: Character passed through unchanged
	// Look for: segBefore + char + segAfter
	passedPattern := segBefore + inputSeq + segAfter
	if strings.Contains(matchStr, passedPattern) {
		return &CharTransform{
			InputChar: ch,
			InputSeq:  inputSeq,
			OutputSeq: inputSeq,
			Transform: TransformPassed,
			SegBefore: segBefore,
			SegAfter:  segAfter,
		}
	}

	// Pattern 2: Backslash escaped
	// Look for: segBefore + \ + char + segAfter
	escapedPattern := segBefore + "\\" + inputSeq + segAfter
	if strings.Contains(matchStr, escapedPattern) {
		return &CharTransform{
			InputChar: ch,
			InputSeq:  inputSeq,
			OutputSeq: "\\" + inputSeq,
			Transform: TransformBackslashEsc,
			SegBefore: segBefore,
			SegAfter:  segAfter,
		}
	}

	// Pattern 3: HTML encoded (for quotes and angle brackets)
	htmlEncoded := ta.checkHTMLEncoding(matchStr, segBefore, segAfter, ch)
	if htmlEncoded != "" {
		return &CharTransform{
			InputChar: ch,
			InputSeq:  inputSeq,
			OutputSeq: htmlEncoded,
			Transform: TransformHTMLEncoded,
			SegBefore: segBefore,
			SegAfter:  segAfter,
		}
	}

	// Pattern 4: URL encoded
	urlEncoded := ta.checkURLEncoding(matchStr, segBefore, segAfter, ch)
	if urlEncoded != "" {
		return &CharTransform{
			InputChar: ch,
			InputSeq:  inputSeq,
			OutputSeq: urlEncoded,
			Transform: TransformURLEncoded,
			SegBefore: segBefore,
			SegAfter:  segAfter,
		}
	}

	// Pattern 5: Character removed - segment before directly adjacent to segment after
	removedPattern := segBefore + segAfter
	if strings.Contains(matchStr, removedPattern) {
		return &CharTransform{
			InputChar: ch,
			InputSeq:  inputSeq,
			OutputSeq: "",
			Transform: TransformRemoved,
			SegBefore: segBefore,
			SegAfter:  segAfter,
		}
	}

	// Unknown transformation
	return &CharTransform{
		InputChar: ch,
		InputSeq:  inputSeq,
		OutputSeq: "",
		Transform: TransformUnknown,
		SegBefore: segBefore,
		SegAfter:  segAfter,
	}
}

// detectSequenceTransform detects transform for multi-char sequences like \'
func (ta *TransformAnalyzer) detectSequenceTransform(
	matchedBytes []byte,
	payload *CanaryPayload,
	seq string,
) *CharTransform {
	if len(seq) == 0 {
		return nil
	}

	// For sequences like \', the first char is the one with segment info
	firstChar := seq[0]
	segBefore := payload.GetSegmentBefore(firstChar)
	segAfter := payload.GetSegmentAfter(firstChar)

	if segBefore == "" || segAfter == "" {
		return nil
	}

	matchStr := string(matchedBytes)

	// Pattern 1: Sequence passed unchanged
	// Input: \' → Output: \'
	passedPattern := segBefore + seq + segAfter
	if strings.Contains(matchStr, passedPattern) {
		return &CharTransform{
			InputChar: seq[len(seq)-1], // The quote char
			InputSeq:  seq,
			OutputSeq: seq,
			Transform: TransformPassed,
			SegBefore: segBefore,
			SegAfter:  segAfter,
		}
	}

	// Pattern 2: Double backslash (exploitable)
	// Input: \' → Output: \\' (backslash was escaped, quote is now unescaped)
	if len(seq) >= 2 && seq[0] == '\\' {
		doubleBackslashPattern := segBefore + "\\\\" + seq[1:] + segAfter
		if strings.Contains(matchStr, doubleBackslashPattern) {
			return &CharTransform{
				InputChar: seq[len(seq)-1],
				InputSeq:  seq,
				OutputSeq: "\\\\" + seq[1:],
				Transform: TransformDoubleBackslash,
				SegBefore: segBefore,
				SegAfter:  segAfter,
			}
		}

		// Pattern 3: Triple backslash (both escaped, not exploitable)
		// Input: \' → Output: \\\'
		tripleBackslashPattern := segBefore + "\\\\\\" + seq[1:] + segAfter
		if strings.Contains(matchStr, tripleBackslashPattern) {
			return &CharTransform{
				InputChar: seq[len(seq)-1],
				InputSeq:  seq,
				OutputSeq: "\\\\\\" + seq[1:],
				Transform: TransformTripleBackslash,
				SegBefore: segBefore,
				SegAfter:  segAfter,
			}
		}
	}

	// Unknown
	return &CharTransform{
		InputChar: seq[len(seq)-1],
		InputSeq:  seq,
		OutputSeq: "",
		Transform: TransformUnknown,
		SegBefore: segBefore,
		SegAfter:  segAfter,
	}
}

// checkHTMLEncoding checks if character was HTML encoded
func (ta *TransformAnalyzer) checkHTMLEncoding(matchStr, segBefore, segAfter string, ch byte) string {
	var encodings []string

	switch ch {
	case '\'':
		encodings = []string{"&#39;", "&apos;", "&#x27;"}
	case '"':
		encodings = []string{"&quot;", "&#34;", "&#x22;"}
	case '<':
		encodings = []string{"&lt;", "&#60;", "&#x3c;", "&#x3C;"}
	case '>':
		encodings = []string{"&gt;", "&#62;", "&#x3e;", "&#x3E;"}
	case '`':
		encodings = []string{"&#96;", "&#x60;", "&grave;"}
	case '$':
		encodings = []string{"&#36;", "&#x24;", "&dollar;", "&dollar"}
	case '&':
		encodings = []string{"&amp;", "&#38;", "&#x26;"}
	default:
		return ""
	}

	for _, enc := range encodings {
		pattern := segBefore + enc + segAfter
		if strings.Contains(matchStr, pattern) {
			return enc
		}
	}

	return ""
}

// checkURLEncoding checks if character was URL encoded
func (ta *TransformAnalyzer) checkURLEncoding(matchStr, segBefore, segAfter string, ch byte) string {
	var encodings []string

	switch ch {
	case '\'':
		encodings = []string{"%27"}
	case '"':
		encodings = []string{"%22"}
	case '<':
		encodings = []string{"%3c", "%3C"}
	case '>':
		encodings = []string{"%3e", "%3E"}
	case '`':
		encodings = []string{"%60"}
	case ' ':
		encodings = []string{"%20", "+"}
	case '/':
		encodings = []string{"%2f", "%2F"}
	case '=':
		encodings = []string{"%3d", "%3D"}
	default:
		return ""
	}

	for _, enc := range encodings {
		pattern := segBefore + enc + segAfter
		if strings.Contains(matchStr, pattern) {
			return enc
		}
	}

	return ""
}
