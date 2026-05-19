package authzutil

import "regexp"

// NameSignal indicates how strongly a parameter name suggests an object identifier.
type NameSignal int

const (
	NoSignal     NameSignal = 0
	MediumSignal NameSignal = 2
	HighSignal   NameSignal = 3
)

// String returns a human-readable label for a NameSignal value.
func (s NameSignal) String() string {
	switch s {
	case HighSignal:
		return "high"
	case MediumSignal:
		return "medium"
	default:
		return "none"
	}
}

// IDType classifies the format of an identifier value.
type IDType int

const (
	Unknown        IDType = iota
	SequentialInt         // 1, 42, 123456
	ShortNumeric          // 1-3 digit numbers (low predictability)
	StructuredCode        // ORD-12345, INV-001-2
	Base64Int             // base64-encoded integer
	UUIDv1                // time-based UUID
	UUIDv4                // random UUID
	Hex                   // 16-64 character hex string
	Email                 // user@example.com
	Slug                  // human-readable-slug
)

// String returns a human-readable label for an IDType value.
func (t IDType) String() string {
	switch t {
	case SequentialInt:
		return "sequential-int"
	case ShortNumeric:
		return "short-numeric"
	case StructuredCode:
		return "structured-code"
	case Base64Int:
		return "base64-int"
	case UUIDv1:
		return "uuid-v1"
	case UUIDv4:
		return "uuid-v4"
	case Hex:
		return "hex"
	case Email:
		return "email"
	case Slug:
		return "slug"
	default:
		return "unknown"
	}
}

// Predictability indicates how easy it is to enumerate or guess an identifier.
type Predictability int

const (
	PredictNone     Predictability = 0
	PredictLow      Predictability = 1
	PredictMedium   Predictability = 2
	PredictHigh     Predictability = 3
	PredictVeryHigh Predictability = 4
)

// String returns a human-readable label for a Predictability value.
func (p Predictability) String() string {
	switch p {
	case PredictVeryHigh:
		return "very-high"
	case PredictHigh:
		return "high"
	case PredictMedium:
		return "medium"
	case PredictLow:
		return "low"
	default:
		return "none"
	}
}

// HighSignalNames are parameter names that strongly indicate object identifiers.
var HighSignalNames = map[string]struct{}{
	"id":             {},
	"uid":            {},
	"user_id":        {},
	"userid":         {},
	"account_id":     {},
	"accountid":      {},
	"order_id":       {},
	"orderid":        {},
	"profile_id":     {},
	"profileid":      {},
	"customer_id":    {},
	"customerid":     {},
	"record_id":      {},
	"recordid":       {},
	"doc_id":         {},
	"docid":          {},
	"invoice_id":     {},
	"invoiceid":      {},
	"transaction_id": {},
	"transactionid":  {},
	"file_id":        {},
	"fileid":         {},
	"message_id":     {},
	"messageid":      {},
	"comment_id":     {},
	"commentid":      {},
	"project_id":     {},
	"projectid":      {},
	"team_id":        {},
	"teamid":         {},
	"org_id":         {},
	"orgid":          {},
	"report_id":      {},
	"reportid":       {},
	"ticket_id":      {},
	"ticketid":       {},
	"session_id":     {},
	"sessionid":      {},
}

// MediumSignalNames are parameter names that may indicate identifiers but are less specific.
var MediumSignalNames = map[string]struct{}{
	"num":    {},
	"number": {},
	"no":     {},
	"ref":    {},
	"key":    {},
	"token":  {},
	"code":   {},
	"handle": {},
	"slug":   {},
	"uuid":   {},
	"guid":   {},
}

// IDSuffixPattern matches parameter names ending with _id, Id, or ID.
var IDSuffixPattern = regexp.MustCompile(`(?i)(.*_)?(id|Id|ID)$`)

// ResourceNouns are URL path segments that typically precede object identifiers.
var ResourceNouns = map[string]struct{}{
	"users":         {},
	"accounts":      {},
	"orders":        {},
	"profiles":      {},
	"customers":     {},
	"invoices":      {},
	"documents":     {},
	"messages":      {},
	"files":         {},
	"tickets":       {},
	"projects":      {},
	"reports":       {},
	"transactions":  {},
	"comments":      {},
	"teams":         {},
	"organizations": {},
	"items":         {},
	"products":      {},
	"payments":      {},
	"subscriptions": {},
	"notifications": {},
	"roles":         {},
	"groups":        {},
	"events":        {},
	"sessions":      {},
	"books":         {},
	"baskets":       {},
	"reviews":       {},
	"posts":         {},
	"articles":      {},
	"blogs":         {},
	"categories":    {},
}

// SensitiveResponseFields are JSON field names in responses that indicate excessive data exposure.
var SensitiveResponseFields = map[string]struct{}{
	"password_hash":   {},
	"password_digest": {},
	"secret_key":      {},
	"private_key":     {},
	"api_secret":      {},
	"internal_id":     {},
	"ssn":             {},
	"social_security": {},
	"credit_card":     {},
	"card_number":     {},
	"cvv":             {},
	"is_admin":        {},
	"isadmin":         {},
	"is_superuser":    {},
	"permissions":     {},
	"access_level":    {},
}

// Value classification patterns.
var (
	SequentialIntPattern  = regexp.MustCompile(`^\d{1,10}$`)
	StructuredCodePattern = regexp.MustCompile(`(?i)^[A-Z]{1,4}-\d{3,10}(-\d+)?$`)
	UUIDv1Pattern         = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	UUIDv4Pattern         = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	HexPattern            = regexp.MustCompile(`(?i)^[0-9a-f]{16,64}$`)
	EmailPattern          = regexp.MustCompile(`(?i)^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

// camelToSnakeRe matches camelCase boundaries for conversion to snake_case.
var camelToSnakeRe = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// NormalizeName converts camelCase and kebab-case parameter names to lowercase snake_case.
func NormalizeName(name string) string {
	// camelCase → snake_case: insert _ before uppercase letters preceded by lowercase/digit
	result := camelToSnakeRe.ReplaceAllString(name, "${1}_${2}")
	// kebab-case → snake_case
	result = replaceHyphens(result)
	return toLower(result)
}

// replaceHyphens replaces hyphens with underscores without allocating when unnecessary.
func replaceHyphens(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			b := make([]byte, len(s))
			copy(b, s)
			for j := i; j < len(s); j++ {
				if s[j] == '-' {
					b[j] = '_'
				}
			}
			return string(b)
		}
	}
	return s
}

// toLower converts ASCII strings to lowercase without allocating when already lowercase.
func toLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := make([]byte, len(s))
			copy(b, s)
			for j := i; j < len(s); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}
