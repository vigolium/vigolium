package padding_oracle

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/infra"
)

// Encoding identifies how a ciphertext candidate was wire-encoded, so a mutated
// ciphertext can be re-encoded in the SAME form the target decodes.
type Encoding int

const (
	// EncodingStdBase64 is standard base64 with padding (RFC 4648 §4).
	EncodingStdBase64 Encoding = iota
	// EncodingRawStdBase64 is standard base64 without padding.
	EncodingRawStdBase64
	// EncodingURLBase64 is URL-safe base64 with padding (RFC 4648 §5).
	EncodingURLBase64
	// EncodingRawURLBase64 is URL-safe base64 without padding.
	EncodingRawURLBase64
	// EncodingHex is lowercase/uppercase hexadecimal.
	EncodingHex
)

// String returns a short label used in finding metadata.
func (e Encoding) String() string {
	switch e {
	case EncodingStdBase64:
		return "base64-std"
	case EncodingRawStdBase64:
		return "base64-rawstd"
	case EncodingURLBase64:
		return "base64-url"
	case EncodingRawURLBase64:
		return "base64-rawurl"
	case EncodingHex:
		return "hex"
	default:
		return "unknown"
	}
}

// Candidate is a decoded ciphertext-shaped value plus the metadata a padding-
// oracle probe needs to mutate and re-encode it.
type Candidate struct {
	Decoded   []byte
	BlockSize int
	Encoding  Encoding
}

// decoderOrder is the fixed order DetectCiphertext tries decoders in; the first
// that both decodes cleanly and passes the block/entropy gates wins.
var decoderOrder = []Encoding{
	EncodingStdBase64,
	EncodingRawStdBase64,
	EncodingURLBase64,
	EncodingRawURLBase64,
	EncodingHex,
}

var (
	// uuidRe matches a canonical UUID (an id, never ciphertext).
	uuidRe = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
	// hexOnlyRe matches an all-hex string (used to exclude plain digests).
	hexOnlyRe = regexp.MustCompile(`^[a-fA-F0-9]+$`)
)

const (
	// minCandidateChars is a cheap floor on the raw value length: two AES blocks
	// (32 bytes) need ~43 base64 chars, so anything much shorter cannot be a
	// 2-block ciphertext and is skipped before any decode work.
	minCandidateChars = 20
	// maxCandidateChars caps the raw value length so a large opaque blob (a minified
	// bundle, a data URI) is not decoded and swept — a session ciphertext is small.
	maxCandidateChars = 4096
	// minEntropyBits is the Shannon-entropy floor (bits/byte) the decoded bytes must
	// clear. Encrypted/compressed bytes approach their length-limited maximum
	// (log2(n)); text and structured data sit well below it.
	minEntropyBits = 3.5
	// maxPrintableRatio is the ceiling on the fraction of decoded bytes that are
	// printable ASCII. Real ciphertext is ~uniformly random (≈0.37 printable);
	// anything that decodes to mostly text/JSON is rejected above this.
	maxPrintableRatio = 0.75
)

// DetectCiphertext reports whether value looks like a block-cipher (CBC)
// ciphertext worth probing for a padding oracle, and if so returns the decoded
// bytes, the inferred block size, and the encoding it decoded from.
//
// It is deliberately conservative: it excludes JWTs, UUIDs, plain hex digests,
// and anything that decodes to printable text/JSON, and it requires a block-
// aligned length of at least two blocks plus high-entropy, mostly-non-printable
// content. It is only ever reached behind a hard "crypto-cbc" tech gate, so a
// permissive false accept still cannot fire without a rigorous active confirmation.
func DetectCiphertext(value string) (Candidate, bool) {
	value = strings.TrimSpace(value)
	if len(value) < minCandidateChars || len(value) > maxCandidateChars {
		return Candidate{}, false
	}

	// Structural exclusions on the raw string.
	if strings.Count(value, ".") >= 2 { // JWT / dotted token
		return Candidate{}, false
	}
	if uuidRe.MatchString(value) {
		return Candidate{}, false
	}
	if isPlainHexDigest(value) {
		return Candidate{}, false
	}

	// Try the URL-unescaped form first (some values arrive percent-encoded), then
	// the raw form. Within each, try the decoders in their fixed order.
	sources := make([]string, 0, 2)
	if un, err := url.QueryUnescape(value); err == nil && un != value {
		sources = append(sources, un)
	}
	sources = append(sources, value)

	for _, src := range sources {
		for _, enc := range decoderOrder {
			decoded, ok := decodeWith(enc, src)
			if !ok {
				continue
			}
			bs, ok := blockSizeFor(len(decoded))
			if !ok {
				continue
			}
			if !looksEncrypted(decoded) {
				continue
			}
			return Candidate{Decoded: decoded, BlockSize: bs, Encoding: enc}, true
		}
	}
	return Candidate{}, false
}

// Reencode re-encodes b in the SAME encoding this candidate decoded from, so a
// mutated ciphertext is transmitted in the exact wire form the target expects.
func (c Candidate) Reencode(b []byte) string {
	switch c.Encoding {
	case EncodingStdBase64:
		return base64.StdEncoding.EncodeToString(b)
	case EncodingRawStdBase64:
		return base64.RawStdEncoding.EncodeToString(b)
	case EncodingURLBase64:
		return base64.URLEncoding.EncodeToString(b)
	case EncodingRawURLBase64:
		return base64.RawURLEncoding.EncodeToString(b)
	case EncodingHex:
		return hex.EncodeToString(b)
	default:
		return base64.StdEncoding.EncodeToString(b)
	}
}

// decodeWith attempts a single decoder against src, returning the decoded bytes
// on a clean, complete decode. A partial or error decode returns ok=false.
func decodeWith(enc Encoding, src string) ([]byte, bool) {
	switch enc {
	case EncodingStdBase64:
		b, err := base64.StdEncoding.DecodeString(src)
		return b, err == nil
	case EncodingRawStdBase64:
		b, err := base64.RawStdEncoding.DecodeString(src)
		return b, err == nil
	case EncodingURLBase64:
		b, err := base64.URLEncoding.DecodeString(src)
		return b, err == nil
	case EncodingRawURLBase64:
		b, err := base64.RawURLEncoding.DecodeString(src)
		return b, err == nil
	case EncodingHex:
		b, err := hex.DecodeString(src)
		return b, err == nil
	default:
		return nil, false
	}
}

// blockSizeFor infers the CBC block size from a decoded length, preferring 16
// (AES) over 8 (3DES/Blowfish). It requires at least two whole blocks so a
// penultimate-block mutation is possible.
func blockSizeFor(n int) (int, bool) {
	if n >= 32 && n%16 == 0 {
		return 16, true
	}
	if n >= 16 && n%8 == 0 {
		return 8, true
	}
	return 0, false
}

// looksEncrypted reports whether decoded bytes resemble ciphertext: high Shannon
// entropy and mostly non-printable content. It rejects values that decode to
// text/JSON (a high printable ratio) or to low-entropy structured data.
func looksEncrypted(decoded []byte) bool {
	if len(decoded) == 0 {
		return false
	}
	printable := 0
	for _, b := range decoded {
		if b >= 0x20 && b <= 0x7e {
			printable++
		}
	}
	if float64(printable)/float64(len(decoded)) > maxPrintableRatio {
		return false
	}
	return infra.ShannonEntropyBits(string(decoded)) >= minEntropyBits
}

// isPlainHexDigest reports whether value is an all-hex string of a common digest
// length (MD5 32, SHA-1 40, SHA-256 64) — a hash, not a ciphertext to probe.
func isPlainHexDigest(value string) bool {
	if !hexOnlyRe.MatchString(value) {
		return false
	}
	switch len(value) {
	case 32, 40, 64:
		return true
	default:
		return false
	}
}
