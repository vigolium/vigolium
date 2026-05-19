package mutation

// ValueType represents the semantic type of a parameter value.
type ValueType int

const (
	TypeUnknown        ValueType = iota
	TypeInteger                  // "123", "0", "-5"
	TypeFloat                    // "3.14", "0.001"
	TypeBoolean                  // "true", "false", "1", "0", "yes", "no"
	TypeUUID                     // "550e8400-e29b-41d4-a716-446655440000"
	TypeEmail                    // "user@example.com"
	TypeTimestamp                // "2026-01-15T10:30:00Z"
	TypeDate                     // "2026-01-15"
	TypeIPv4                     // "192.168.1.10"
	TypeIPv6                     // "::1", "fe80::1"
	TypePath                     // "/api/v1/users"
	TypeEnum                     // Detected from OpenAPI spec or pattern matching
	TypeSequentialID             // "1001" (numeric, in ID-like context)
	TypeStructuredCode           // "ORD-00042", "INV-2024-001"
	TypeJWT                      // "eyJhbGciOi..."
	TypeBase64                   // Valid base64-encoded content
	TypeHexEncoded               // "4a6f686e" (hex-encoded)
	TypeURL                      // "https://example.com/callback"
	TypePhoneNumber              // "+1-555-123-4567"
	TypeCreditCard               // "4532015112830366" (Luhn-valid)
	TypeSlug                     // "my-blog-post", "user_profile_page"
	TypeJSON                     // '{"key":"value"}'
	TypeEmpty                    // ""
)

// String returns the human-readable name of the ValueType.
func (v ValueType) String() string {
	switch v {
	case TypeUnknown:
		return "unknown"
	case TypeInteger:
		return "integer"
	case TypeFloat:
		return "float"
	case TypeBoolean:
		return "boolean"
	case TypeUUID:
		return "uuid"
	case TypeEmail:
		return "email"
	case TypeTimestamp:
		return "timestamp"
	case TypeDate:
		return "date"
	case TypeIPv4:
		return "ipv4"
	case TypeIPv6:
		return "ipv6"
	case TypePath:
		return "path"
	case TypeEnum:
		return "enum"
	case TypeSequentialID:
		return "sequential_id"
	case TypeStructuredCode:
		return "structured_code"
	case TypeJWT:
		return "jwt"
	case TypeBase64:
		return "base64"
	case TypeHexEncoded:
		return "hex_encoded"
	case TypeURL:
		return "url"
	case TypePhoneNumber:
		return "phone_number"
	case TypeCreditCard:
		return "credit_card"
	case TypeSlug:
		return "slug"
	case TypeJSON:
		return "json"
	case TypeEmpty:
		return "empty"
	default:
		return "unknown"
	}
}

// MutationIntent describes the purpose of a mutation set.
type MutationIntent int

const (
	IntentNeighbor   MutationIntent = iota // Semantically close variants (increment, swap)
	IntentBoundary                         // Edge cases, limits, overflows
	IntentEscalation                       // Privilege escalation variants
	IntentFormat                           // Format/type confusion
	IntentEmpty                            // Null, empty, undefined
)

// String returns the human-readable name of the MutationIntent.
func (m MutationIntent) String() string {
	switch m {
	case IntentNeighbor:
		return "neighbor"
	case IntentBoundary:
		return "boundary"
	case IntentEscalation:
		return "escalation"
	case IntentFormat:
		return "format"
	case IntentEmpty:
		return "empty"
	default:
		return "unknown"
	}
}

// Mutation represents a single mutated value with metadata.
type Mutation struct {
	Value  string         // The mutated value
	Intent MutationIntent // Why this mutation was generated
	Label  string         // Human-readable description (e.g., "increment by 1")
}

// MutationSet holds classified mutations for a single insertion point.
type MutationSet struct {
	OriginalValue string
	DetectedType  ValueType
	Mutations     []Mutation
}

// SchemaHint provides optional type information from OpenAPI or other specs.
type SchemaHint struct {
	Type      string   // "integer", "string", "boolean", "number"
	Format    string   // "uuid", "email", "date-time", "uri", etc.
	Enum      []string // Allowed values from spec
	Minimum   *float64 // Minimum value constraint
	Maximum   *float64 // Maximum value constraint
	MinLength *int     // Minimum string length
	MaxLength *int     // Maximum string length
	Pattern   string   // Regex pattern from spec
	ParamName string   // Parameter name for context-aware detection
}

// GenerateOptions controls variant generation.
type GenerateOptions struct {
	Intents      []MutationIntent // Which intents to include (default: all)
	MaxPerIntent int              // Max mutations per intent (default: 5)
	SchemaHint   *SchemaHint      // Optional spec constraints
}

// DefaultGenerateOptions returns default generation options.
func DefaultGenerateOptions() *GenerateOptions {
	return &GenerateOptions{
		Intents: []MutationIntent{
			IntentNeighbor,
			IntentBoundary,
			IntentEscalation,
			IntentFormat,
			IntentEmpty,
		},
		MaxPerIntent: 5,
	}
}

// hasIntent checks whether the given intent is in the options.
func (o *GenerateOptions) hasIntent(intent MutationIntent) bool {
	if o == nil || len(o.Intents) == 0 {
		return true // all intents enabled by default
	}
	for _, i := range o.Intents {
		if i == intent {
			return true
		}
	}
	return false
}
