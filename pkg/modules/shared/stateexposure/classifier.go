package stateexposure

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Hit is a value-safe classification of security-relevant serialized state.
// Evidence deliberately describes the value without copying it into findings.
type Hit struct {
	Category  string `json:"category"`
	Field     string `json:"field,omitempty"`
	Evidence  string `json:"evidence"`
	Reason    string `json:"reason"`
	Candidate bool   `json:"candidate"`
}

var (
	jsonStringPair = regexp.MustCompile(`"([^"\\]+)"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"`)
	jsonBoolPair   = regexp.MustCompile(`(?i)"([^"\\]+)"\s*:\s*(true|false)`)
	publicID       = regexp.MustCompile(`^(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|pk_(?:live|test)_[0-9A-Za-z]{16,})$`)
	privateToken   = regexp.MustCompile(`^(?:gh[pousr]_[0-9A-Za-z]{36,255}|xox[abprs]-[0-9A-Za-z-]{10,}|sk_live_[0-9A-Za-z]{16,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)`)
	passwordHash   = regexp.MustCompile(`(?i)^(?:\$2[aby]\$|\$argon2|pbkdf2|scrypt|sha(?:256|512)[:$])`)
	emailValue     = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

var credentialFields = map[string]string{
	"password": "Password", "passwd": "Password", "passwordhash": "Password Hash", "hashedpassword": "Password Hash",
	"apikey": "API Key/Token", "apitoken": "API Key/Token", "accesstoken": "API Key/Token",
	"secretkey": "API Key/Token", "authtoken": "API Key/Token", "clientsecret": "API Key/Token",
	"privatekey": "Private Key",
}

var identityFields = map[string]string{
	"email": "Email Address", "mail": "Email Address", "useremail": "Email Address",
	"isadmin": "Privilege/Role", "issuperuser": "Privilege/Role", "isstaff": "Privilege/Role",
	"admin": "Privilege/Role", "role": "Privilege/Role",
}

// Analyze classifies JSON or JavaScript-object-like serialized state. It first
// walks valid JSON and then falls back to conservative quoted key/value parsing
// for assignment blobs that are not standalone JSON.
func Analyze(state string) []Hit {
	var rawHits []Hit
	var document any
	if json.Unmarshal([]byte(strings.TrimSpace(state)), &document) == nil {
		walk(document, "", &rawHits)
	} else {
		for _, pair := range jsonStringPair.FindAllStringSubmatch(state, -1) {
			if len(pair) == 3 {
				rawHits = append(rawHits, classifyString(pair[1], pair[2])...)
			}
		}
		for _, pair := range jsonBoolPair.FindAllStringSubmatch(state, -1) {
			if len(pair) == 3 {
				rawHits = append(rawHits, classifyBool(pair[1], strings.EqualFold(pair[2], "true"))...)
			}
		}
	}
	return deduplicate(rawHits)
}

func walk(node any, field string, hits *[]Hit) {
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			switch scalar := value.(type) {
			case string:
				*hits = append(*hits, classifyString(key, scalar)...)
			case bool:
				*hits = append(*hits, classifyBool(key, scalar)...)
			}
			walk(value, key, hits)
		}
	case []any:
		for _, value := range typed {
			walk(value, field, hits)
		}
	}
}

func classifyString(field, value string) []Hit {
	trimmed := strings.TrimSpace(value)
	normalized := normalize(field)
	lengthEvidence := fmt.Sprintf("field %q contains a %d-character value", field, len(trimmed))

	if category, ok := credentialFields[normalized]; ok {
		if isPlaceholderExampleOrMasked(trimmed) {
			return []Hit{{Category: category, Field: field, Evidence: lengthEvidence, Reason: "credential-shaped field contains placeholder, example, or masked data", Candidate: false}}
		}
		if publicID.MatchString(trimmed) {
			return []Hit{{Category: "Public Credential Identifier", Field: field, Evidence: lengthEvidence, Reason: "value matches a public identifier format, not a private credential", Candidate: false}}
		}
		if privateToken.MatchString(trimmed) || passwordHash.MatchString(trimmed) {
			return []Hit{{Category: category, Field: field, Evidence: lengthEvidence, Reason: "value matches a private token, private key, or password-hash format", Candidate: true}}
		}
		minimum := 16
		if normalized == "password" || normalized == "passwd" {
			minimum = 4
		}
		if len(trimmed) >= minimum {
			return []Hit{{Category: category, Field: field, Evidence: lengthEvidence, Reason: "credential-shaped field carries a substantive non-public value; validity was not tested", Candidate: true}}
		}
		return []Hit{{Category: category, Field: field, Evidence: lengthEvidence, Reason: "credential-shaped field is present, but the value is too short to support secret inference", Candidate: false}}
	}

	if category, ok := identityFields[normalized]; ok {
		if (category == "Email Address" && emailValue.MatchString(trimmed)) || (category == "Privilege/Role" && trimmed != "") {
			return []Hit{{Category: category, Field: field, Evidence: lengthEvidence, Reason: "identity or role data is normal client state unless an authorization differential proves overexposure", Candidate: false}}
		}
	}

	if publicID.MatchString(trimmed) {
		return []Hit{{Category: "Public Credential Identifier", Field: field, Evidence: lengthEvidence, Reason: "AWS access-key IDs, Google API keys, and publishable Stripe keys are identifiers, not private secret material", Candidate: false}}
	}
	if databaseURL, ok := classifyDatabaseURL(field, trimmed); ok {
		return []Hit{databaseURL}
	}
	if address := privateAddress(trimmed); address != "" {
		return []Hit{{Category: "Internal Address", Field: field, Evidence: fmt.Sprintf("field %q contains a valid private-network address", field), Reason: "internal topology is reconnaissance context; no internal reachability is implied", Candidate: false}}
	}
	return nil
}

func classifyBool(field string, value bool) []Hit {
	normalized := normalize(field)
	category, ok := identityFields[normalized]
	if !ok || category != "Privilege/Role" {
		return nil
	}
	return []Hit{{
		Category: "Privilege/Role", Field: field,
		Evidence:  fmt.Sprintf("field %q is the boolean %t", field, value),
		Reason:    "a role flag describes the current serialized identity; it does not prove privilege escalation or cross-user exposure",
		Candidate: false,
	}}
}

func classifyDatabaseURL(field, value string) (Hit, bool) {
	parsed, err := url.Parse(value)
	if err != nil {
		return Hit{}, false
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis", "amqp", "amqps":
	default:
		return Hit{}, false
	}
	candidate := false
	if parsed.User != nil {
		if password, set := parsed.User.Password(); set && password != "" && !isPlaceholderExampleOrMasked(password) {
			candidate = true
		}
	}
	reason := "service URL contains no substantive embedded password; endpoint visibility is reconnaissance context"
	if candidate {
		reason = "database or queue URL contains a substantive embedded password; credential validity and network reachability were not tested"
	}
	return Hit{
		Category: "Database/Service URL", Field: field,
		Evidence: fmt.Sprintf("field %q contains a %s service URL", field, scheme),
		Reason:   reason, Candidate: candidate,
	}, true
}

func privateAddress(value string) string {
	host := value
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	} else if candidate, _, err := net.SplitHostPort(value); err == nil {
		host = candidate
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip != nil && ip.IsPrivate() {
		return ip.String()
	}
	return ""
}

func normalize(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

func isPlaceholderExampleOrMasked(value string) bool {
	if modkit.IsPlaceholderValue(value) {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"example", "placeholder", "changeme", "change_me", "dummy", "sample", "redacted", "masked", "your_", "your-"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.Trim(value, "*xX._- ") == ""
}

func deduplicate(hits []Hit) []Hit {
	unique := make(map[string]Hit)
	for _, hit := range hits {
		key := hit.Category + "|" + hit.Field + "|" + fmt.Sprint(hit.Candidate)
		unique[key] = hit
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Hit, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result
}
