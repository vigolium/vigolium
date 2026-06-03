package infra

// IsNumericValue reports whether s looks like a numeric parameter value (an
// optional leading sign, digits, and decimal points). SQLi modules use it to
// pick numeric- vs string-context payloads for an insertion point.
func IsNumericValue(s string) bool {
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
