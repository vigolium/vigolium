package xss_light_scanner

// BypassPrefix defines prefix bytes to prepend to payload
// These prefixes can interrupt escape functions in various backends
type BypassPrefix struct {
	Name  string // Identifier for logging/debugging
	Bytes []byte // Prefix bytes (nil for no prefix)
}

// BypassPrefixes defines all prefix variants to try sequentially
// Order matters: standard (no prefix) is tried first
var BypassPrefixes = []BypassPrefix{
	{Name: "none", Bytes: nil},                // Standard - try first
	{Name: "null", Bytes: []byte{0x00}},       // Null byte - truncate/confuse escape
	{Name: "ff", Bytes: []byte{0xff}},         // 0xFF - encoding edge cases
	{Name: "crlf", Bytes: []byte{0x0d, 0x0a}}, // CRLF - line-based processing bypass
}

// HasPrefix returns true if this is not the standard (no prefix) variant
func (bp BypassPrefix) HasPrefix() bool {
	return len(bp.Bytes) > 0
}

// String returns human-readable representation
func (bp BypassPrefix) String() string {
	return bp.Name
}
