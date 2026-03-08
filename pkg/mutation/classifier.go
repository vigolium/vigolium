package mutation

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Classify detects the semantic ValueType of a raw string value.
// An optional SchemaHint provides overrides from OpenAPI or other specs.
// The hint's ParamName field provides context-aware classification boosting.
func Classify(value string, hint *SchemaHint) ValueType {
	// 1. SchemaHint overrides
	if hint != nil {
		if vt := classifyFromHint(hint, value); vt != TypeUnknown {
			return vt
		}
	}

	// 2. Empty
	if value == "" {
		return TypeEmpty
	}

	// Get param name for context-aware boosting
	paramName := ""
	if hint != nil {
		paramName = hint.ParamName
	}

	// 3. Boolean
	if isBoolean(value) {
		return TypeBoolean
	}

	// 4. UUID
	if reUUID.MatchString(value) {
		return TypeUUID
	}

	// 5. JWT
	if isJWT(value) {
		return TypeJWT
	}

	// 6. Email
	if reEmail.MatchString(value) {
		return TypeEmail
	}

	// 7. IPv4
	if isIPv4(value) {
		return TypeIPv4
	}

	// 8. IPv6
	if isIPv6(value) {
		return TypeIPv6
	}

	// 9. Timestamp (ISO 8601 with time)
	if reTimestamp.MatchString(value) {
		return TypeTimestamp
	}

	// 10. Date (ISO 8601 date only)
	if reDate.MatchString(value) {
		return TypeDate
	}

	// 11. Structured code (e.g., ORD-00042)
	if reStructuredCode.MatchString(value) {
		return TypeStructuredCode
	}

	// 12. Credit card (13-19 digits, Luhn check) — must come before phone number
	if isCreditCard(value) {
		return TypeCreditCard
	}

	// 13. Phone number
	if rePhoneNumber.MatchString(value) && len(value) >= 8 {
		return TypePhoneNumber
	}

	// 14. Float
	if reFloat.MatchString(value) {
		// Check context: might be a price/amount
		return TypeFloat
	}

	// 15. Integer
	if reInteger.MatchString(value) {
		// Context-aware: ID-like param names boost to SequentialID
		if isIDParamName(paramName) {
			return TypeSequentialID
		}
		return TypeInteger
	}

	// 16. Hex-encoded (even length, >= 16 chars)
	if reHexEncoded.MatchString(value) {
		return TypeHexEncoded
	}

	// 17. Base64
	if isBase64(value) {
		return TypeBase64
	}

	// 18. URL
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return TypeURL
	}

	// 19. JSON
	if isJSON(value) {
		return TypeJSON
	}

	// 20. Path
	if strings.HasPrefix(value, "/") && len(value) > 1 {
		return TypePath
	}

	// 21. Slug
	if reSlug.MatchString(value) {
		return TypeSlug
	}

	// 22. Enum (only if SchemaHint provides enum values)
	if hint != nil && len(hint.Enum) > 0 {
		for _, e := range hint.Enum {
			if e == value {
				return TypeEnum
			}
		}
	}

	// Context-aware: check param name patterns for common enum-like values
	if isEnumParamName(paramName) {
		return TypeEnum
	}

	// 23. Unknown
	return TypeUnknown
}

// classifyFromHint applies schema hint overrides.
func classifyFromHint(hint *SchemaHint, value string) ValueType {
	// Format-based overrides (most specific)
	switch strings.ToLower(hint.Format) {
	case "uuid":
		return TypeUUID
	case "email":
		return TypeEmail
	case "date-time", "datetime":
		return TypeTimestamp
	case "date":
		return TypeDate
	case "uri", "url":
		return TypeURL
	case "ipv4":
		return TypeIPv4
	case "ipv6":
		return TypeIPv6
	case "byte":
		return TypeBase64
	}

	// Type-based overrides
	switch strings.ToLower(hint.Type) {
	case "integer":
		if isIDParamName(hint.ParamName) {
			return TypeSequentialID
		}
		return TypeInteger
	case "number":
		// Check if value has decimal
		if strings.Contains(value, ".") {
			return TypeFloat
		}
		return TypeInteger
	case "boolean":
		return TypeBoolean
	}

	// Enum override
	if len(hint.Enum) > 0 {
		return TypeEnum
	}

	return TypeUnknown
}

// --- Boolean detection ---

var booleanValues = map[string]bool{
	"true": true, "false": true,
	"yes": true, "no": true,
	"on": true, "off": true,
}

func isBoolean(value string) bool {
	_, ok := booleanValues[strings.ToLower(value)]
	return ok
}

// --- Compiled regex patterns ---

var (
	reUUID           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reEmail          = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$`)
	reTimestamp      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`)
	reDate           = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reStructuredCode = regexp.MustCompile(`^[A-Z]{1,5}-\d{2,10}(-\d+)?$`)
	rePhoneNumber    = regexp.MustCompile(`^\+?\d[\d\s\-()]{7,}$`)
	reFloat          = regexp.MustCompile(`^-?\d+\.\d+$`)
	reInteger        = regexp.MustCompile(`^-?\d+$`)
	reHexEncoded     = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	reSlug           = regexp.MustCompile(`^[a-z0-9]+([_-][a-z0-9]+)+$`)
)

// --- IPv4 detection ---

func isIPv4(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// --- IPv6 detection ---

func isIPv6(value string) bool {
	if !strings.Contains(value, ":") {
		return false
	}
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() == nil
}

// --- JWT detection ---

func isJWT(value string) bool {
	if !strings.HasPrefix(value, "eyJ") {
		return false
	}
	parts := strings.Split(value, ".")
	return len(parts) == 3
}

// --- Credit card detection (Luhn check) ---

func isCreditCard(value string) bool {
	// Must be all digits, 13-19 chars
	if len(value) < 13 || len(value) > 19 {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return luhnCheck(value)
}

func luhnCheck(number string) bool {
	sum := 0
	alt := false
	for i := len(number) - 1; i >= 0; i-- {
		n := int(number[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// --- Base64 detection ---

func isBase64(value string) bool {
	if len(value) < 8 {
		return false
	}
	// Reject values that look like paths, slugs, or natural text
	if strings.HasPrefix(value, "/") {
		return false
	}
	if strings.Contains(value, " ") {
		return false
	}
	// Must contain base64 alphabet only (A-Z, a-z, 0-9, +, /, =) or URL-safe (-, _)
	// Reject if it looks like a slug (lowercase with dashes/underscores only)
	if reSlug.MatchString(value) {
		return false
	}
	// Must not be a common word (all alpha, no special chars)
	if isCommonWord(value) {
		return false
	}
	// Require padding ('=') or look for mixed case + digits typical of base64
	hasPadding := strings.HasSuffix(value, "=")
	hasMixedCharset := false
	hasUpper, hasLower, hasDigit := false, false, false
	for _, r := range value {
		if unicode.IsUpper(r) {
			hasUpper = true
		} else if unicode.IsLower(r) {
			hasLower = true
		} else if unicode.IsDigit(r) {
			hasDigit = true
		}
	}
	hasMixedCharset = (hasUpper && hasLower && hasDigit) || (hasUpper && hasDigit) || (hasLower && hasDigit && hasUpper)
	if !hasPadding && !hasMixedCharset {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(value)
		if err != nil {
			return false
		}
	}
	if len(decoded) == 0 {
		return false
	}
	return true
}

func isCommonWord(value string) bool {
	for _, r := range value {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return len(value) < 24
}

// --- JSON detection ---

func isJSON(value string) bool {
	if len(value) < 2 {
		return false
	}
	if value[0] != '{' && value[0] != '[' {
		return false
	}
	var js json.RawMessage
	return json.Unmarshal([]byte(value), &js) == nil
}

// --- Context-aware parameter name patterns ---

var idParamPatterns = []string{
	"_id", "Id", "ID",
}

func isIDParamName(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	if lower == "id" {
		return true
	}
	for _, pattern := range idParamPatterns {
		if strings.HasSuffix(name, pattern) {
			return true
		}
	}
	// Check common ID param names
	switch lower {
	case "uid", "userid", "user_id", "account_id", "accountid",
		"member_id", "memberid", "order_id", "orderid",
		"product_id", "productid", "item_id", "itemid",
		"record_id", "recordid", "ref", "key":
		return true
	}
	return false
}

var enumParamNames = map[string]bool{
	"role": true, "status": true, "type": true, "level": true,
	"permission": true, "access_level": true, "user_role": true,
	"state": true, "category": true, "priority": true,
	"visibility": true, "scope": true, "tier": true,
}

func isEnumParamName(name string) bool {
	if name == "" {
		return false
	}
	return enumParamNames[strings.ToLower(name)]
}
