package backslash_transformation

import (
	"math/rand/v2"
)

// AnchoredPayload represents a payload with anchors for reflection extraction.
type AnchoredPayload struct {
	LeftAnchor   string // Random 3-5 chars to locate reflection start
	MiddleAnchor string // "z" + digit between left anchor and probe
	RightAnchor  string // "z" + random chars to locate reflection end
	FullPayload  string // Complete payload: leftAnchor + \\ + middleAnchor + probe + rightAnchor
	Probe        string // The escape sequence or character being tested
}

// DecodeBasedPayloads are escape sequences that test decode behavior.
// Each should decode to a specific character if interpreted:
// - \101 -> 'A' (octal)
// - \x41 -> 'A' (hex)
// - \u0041 -> 'A' (unicode)
// - \0 -> NULL (null byte)
// - \1 -> SOH (control char)
// - \x0 -> varies (truncated hex)
var DecodeBasedPayloads = []string{
	"\\101",   // Octal escape -> 'A'
	"\\x41",   // Hex escape -> 'A'
	"\\u0041", // Unicode escape -> 'A'
	"\\0",     // Null byte escape
	"\\1",     // Control character escape
	"\\x0",    // Truncated/invalid hex
}

// CharacterPayloads are special characters to test handling.
// These are tested with and without backslash prefix depending on backslashConsumed.
var CharacterPayloads = []string{
	"'",  // Single quote
	"\"", // Double quote
	"{",  // Opening brace
	"}",  // Closing brace
	"(",  // Opening paren
	")",  // Closing paren
	"[",  // Opening bracket
	"]",  // Closing bracket
	"$",  // Dollar sign (variable expansion)
	"`",  // Backtick (command substitution)
	"/",  // Forward slash (path)
	"@",  // At sign
	"#",  // Hash
	";",  // Semicolon (command separator)
	"%",  // Percent (encoding)
	"&",  // Ampersand
	"|",  // Pipe
	"^",  // Caret
	"?",  // Question mark
}

// randomLowerString generates a random lowercase alphanumeric string.
func randomLowerString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}

// NewAnchoredPayload creates a new anchored payload for probing.
// The payload format is: leftAnchor + \\ + middleAnchor + probe + rightAnchor
// When reflected, we look for: leftAnchor + \ + middleAnchor + <transformed_probe> + rightAnchor
func NewAnchoredPayload(probe string) *AnchoredPayload {
	leftAnchor := randomLowerString(3)
	middleAnchor := "z" + string('0'+byte(rand.IntN(10))) // z0-z9
	rightAnchor := "z" + randomLowerString(3)             // z + 3 random chars

	return &AnchoredPayload{
		LeftAnchor:   leftAnchor,
		MiddleAnchor: middleAnchor,
		RightAnchor:  rightAnchor,
		FullPayload:  leftAnchor + "\\\\" + middleAnchor + probe + rightAnchor,
		Probe:        probe,
	}
}

// SearchAnchor returns the anchor pattern to search for in the response.
// This is: leftAnchor + \ + middleAnchor (single backslash after URL encoding round-trip)
func (ap *AnchoredPayload) SearchAnchor() string {
	return ap.LeftAnchor + "\\" + ap.MiddleAnchor
}

// NewBasicReflectionPayload creates a simple payload to check if parameter reflects.
// Format: leftAnchor + \\ + rightAnchor
func NewBasicReflectionPayload() (payload string, searchAnchor string) {
	leftAnchor := randomLowerString(5)
	rightAnchor := "z" + randomLowerString(2)
	payload = leftAnchor + "\\\\" + rightAnchor
	searchAnchor = leftAnchor + "\\" + rightAnchor
	return
}

// NewBackslashConsumptionPayload creates a payload to test if backslashes are consumed.
// Format: leftAnchor + \\ + middleAnchor + \\zz + rightAnchor
// If "zz" appears without backslash in reflection, backslash is being consumed.
func NewBackslashConsumptionPayload() (payload string, leftSearch string, middleAnchor string, rightAnchor string) {
	leftAnchor := randomLowerString(3)
	middleAnchor = "z" + string('0'+byte(rand.IntN(10)))
	rightAnchor = "z" + randomLowerString(3)

	payload = leftAnchor + "\\\\" + middleAnchor + "\\\\zz" + rightAnchor
	leftSearch = leftAnchor + "\\" + middleAnchor
	return
}
