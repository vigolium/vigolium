package severity

import (
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

type Severity int

// name:Severity
const (
	// name:undefined
	Undefined Severity = iota
	// name:info
	Info
	// name:suspect
	Suspect
	// name:low
	Low
	// name:medium
	Medium
	// name:high
	High
	// name:critical
	Critical
)

var severityMappings = map[Severity]string{
	Info:     "info",
	Suspect:  "suspect",
	Low:      "low",
	Medium:   "medium",
	High:     "high",
	Critical: "critical",
}

// AllNames returns all known severity names in least-to-most-severe order,
// suitable for JSON schema enums or display.
func AllNames() []string {
	return []string{"info", "suspect", "low", "medium", "high", "critical"}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return jsoniter.Marshal(s.String())
}

func toSeverity(valueToMap string) (Severity, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range severityMappings {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid severity: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (severity Severity) String() string {
	return severityMappings[severity]
}

// Confidence represents the confidence level of a finding.
type Confidence int

const (
	ConfidenceUndefined Confidence = iota
	Tentative                      // Possible but unconfirmed (e.g., heuristic-based detection)
	Firm                           // Likely confirmed by behavioral analysis
	Certain                        // Definitively confirmed (e.g., payload executed, error matched)
)

var confidenceMappings = map[Confidence]string{
	Tentative: "tentative",
	Firm:      "firm",
	Certain:   "certain",
}

func (c Confidence) String() string {
	if s, ok := confidenceMappings[c]; ok {
		return s
	}
	return "firm"
}

func (c Confidence) MarshalJSON() ([]byte, error) {
	return jsoniter.Marshal(c.String())
}

// ToConfidence parses a string into a Confidence value.
func ToConfidence(s string) Confidence {
	switch normalizeValue(s) {
	case "certain":
		return Certain
	case "firm":
		return Firm
	case "tentative":
		return Tentative
	default:
		return ConfidenceUndefined
	}
}
