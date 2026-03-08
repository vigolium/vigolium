package authzutil

import (
	"encoding/base64"
	"strconv"
	"strings"
	"unicode"
)

// IDClassification holds the full classification result for a parameter.
type IDClassification struct {
	IsObjectID    bool
	IDType        IDType
	Predictability Predictability
	NameSignal    NameSignal
	NameScore     int
	ValueScore    int
	PathScore     int
	TotalScore    int
	ResourceNoun  string
}

// ClassifyParamName evaluates whether a parameter name looks like an object identifier.
func ClassifyParamName(name string) (NameSignal, int) {
	normalized := NormalizeName(name)

	if _, ok := HighSignalNames[normalized]; ok {
		return HighSignal, 3
	}
	if _, ok := MediumSignalNames[normalized]; ok {
		return MediumSignal, 2
	}
	if IDSuffixPattern.MatchString(name) {
		return HighSignal, 3
	}
	return NoSignal, 0
}

// ClassifyParamValue determines the type and predictability of an identifier value.
func ClassifyParamValue(value string) (IDType, Predictability, int) {
	if value == "" {
		return Unknown, PredictNone, 0
	}

	// Sequential integer (1-10 digits)
	if SequentialIntPattern.MatchString(value) {
		// Short numbers (1-3 digits) are very common IDs but could also be enum values
		if len(value) <= 3 {
			return SequentialInt, PredictVeryHigh, 3
		}
		return SequentialInt, PredictVeryHigh, 3
	}

	// Structured code: ORD-12345
	if StructuredCodePattern.MatchString(value) {
		return StructuredCode, PredictHigh, 3
	}

	// Base64-encoded integer
	if idType, pred, score := tryBase64Int(value); idType != Unknown {
		return idType, pred, score
	}

	// UUIDv1 (time-based, more predictable)
	if UUIDv1Pattern.MatchString(value) {
		return UUIDv1, PredictMedium, 2
	}

	// Email
	if EmailPattern.MatchString(value) {
		return Email, PredictMedium, 2
	}

	// UUIDv4 (random)
	if UUIDv4Pattern.MatchString(value) {
		return UUIDv4, PredictLow, 1
	}

	// Hex string (16-64 chars)
	if HexPattern.MatchString(value) {
		return Hex, PredictLow, 1
	}

	return Unknown, PredictNone, 0
}

// tryBase64Int checks if the value is a base64-encoded integer.
func tryBase64Int(value string) (IDType, Predictability, int) {
	// Base64 strings are typically 4+ characters and contain only base64 chars
	if len(value) < 2 || len(value) > 20 {
		return Unknown, PredictNone, 0
	}

	// Quick check for base64-like characters
	for _, r := range value {
		if !isBase64Char(r) {
			return Unknown, PredictNone, 0
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
		if err != nil {
			return Unknown, PredictNone, 0
		}
	}

	// Check if decoded content is a numeric string
	s := strings.TrimSpace(string(decoded))
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return Base64Int, PredictHigh, 3
	}

	return Unknown, PredictNone, 0
}

// isBase64Char checks if a rune is a valid base64 character.
func isBase64Char(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '+' || r == '/' || r == '='
}

// ClassifyPathContext checks if a value appears in a URL path immediately after a resource noun.
func ClassifyPathContext(pathSegments []string, segmentValue string) (string, int) {
	if segmentValue == "" || len(pathSegments) < 2 {
		return "", 0
	}

	for i, seg := range pathSegments {
		if seg == segmentValue && i > 0 {
			prev := strings.ToLower(pathSegments[i-1])
			if _, ok := ResourceNouns[prev]; ok {
				return prev, 2
			}
		}
	}

	// Value looks like an ID but no resource noun precedes it
	if isIDLikeValue(segmentValue) {
		return "", 1
	}

	return "", 0
}

// isIDLikeValue checks if a string looks like an identifier (number, UUID, hex, etc.).
func isIDLikeValue(value string) bool {
	return SequentialIntPattern.MatchString(value) ||
		UUIDv4Pattern.MatchString(value) ||
		UUIDv1Pattern.MatchString(value) ||
		HexPattern.MatchString(value) ||
		StructuredCodePattern.MatchString(value)
}

// ClassifyParam performs full classification of a parameter as a potential object identifier.
func ClassifyParam(name, value string, isPathParam bool, pathSegments []string) IDClassification {
	nameSignal, nameScore := ClassifyParamName(name)
	idType, predictability, valueScore := ClassifyParamValue(value)

	var resourceNoun string
	var pathScore int
	if isPathParam && len(pathSegments) > 0 {
		resourceNoun, pathScore = ClassifyPathContext(pathSegments, value)
	}

	totalScore := nameScore + valueScore + pathScore

	return IDClassification{
		IsObjectID:    totalScore >= 3,
		IDType:        idType,
		Predictability: predictability,
		NameSignal:    nameSignal,
		NameScore:     nameScore,
		ValueScore:    valueScore,
		PathScore:     pathScore,
		TotalScore:    totalScore,
		ResourceNoun:  resourceNoun,
	}
}
