package race_interference

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

// FindingType represents the type of race condition finding.
type FindingType int

const (
	FindingInputStorage FindingType = iota
	FindingCrossContamination
	FindingRequestInterference
)

// String returns a human-readable name for the finding type.
func (f FindingType) String() string {
	switch f {
	case FindingInputStorage:
		return "Input Storage"
	case FindingCrossContamination:
		return "Cross-contamination Race Condition"
	case FindingRequestInterference:
		return "Request Interference Race Condition"
	default:
		return "Unknown"
	}
}

// Finding represents a detected race condition vulnerability.
type Finding struct {
	Type        FindingType
	Parameter   string
	Anchor      string
	WrongIdSeen string
	Request     string
	Response    string
}

// Severity returns the per-result severity. Wrong-id signals are confined to
// one scanner identity, so they remain Medium candidates. Divergence alone is
// informational until a state or authorization impact is shown.
func (f *Finding) Severity() severity.Severity {
	switch f.Type {
	case FindingRequestInterference:
		return severity.Info
	default:
		return severity.Medium
	}
}

// Confidence returns the per-finding confidence. Request Interference is
// downgraded to Tentative for the same reason as Severity above.
func (f *Finding) Confidence() severity.Confidence {
	switch f.Type {
	case FindingRequestInterference:
		return severity.Tentative
	default:
		return ModuleConfidence
	}
}

// buildDescription generates a markdown description for the finding.
func (f *Finding) buildDescription() string {
	var sb strings.Builder

	switch f.Type {
	case FindingInputStorage:
		sb.WriteString("**Input Storage Candidate (Same Session)**\n\n")
		sb.WriteString("The application stores user input from URL parameters and includes it in subsequent responses. ")
		sb.WriteString("The effect reproduced with a fresh canary, but every request used the same scanner identity. ")
		sb.WriteString("Cross-user cache poisoning, stored XSS, and session leakage are not established.\n")

	case FindingCrossContamination:
		sb.WriteString("**Cross-contamination Candidate (Same Session)**\n\n")
		sb.WriteString("When parallel requests are sent, data from one request appears in the response ")
		sb.WriteString("of another request. The effect reproduced with a fresh canary, but does not prove ")
		sb.WriteString("data crosses user or authentication boundaries.\n")

	case FindingRequestInterference:
		sb.WriteString("**Concurrent Response Divergence Observed**\n\n")
		sb.WriteString("Parallel requests cause divergent responses compared to sequential baseline. ")
		sb.WriteString("Sequential controls stayed stable, but divergence alone does not establish a TOCTOU, ")
		sb.WriteString("business-logic bypass, privilege escalation, or durable state change.\n")
	}

	// Add technical details
	sb.WriteString("\n### Technical Details\n")
	fmt.Fprintf(&sb, "- **Parameter**: `%s`\n", f.Parameter)
	fmt.Fprintf(&sb, "- **Canary**: `%s`\n", f.Anchor)
	if f.WrongIdSeen != "" {
		fmt.Fprintf(&sb, "- **Wrong ID detected**: `%s`\n", f.WrongIdSeen)
	}

	// Add references
	sb.WriteString("\n### References\n")
	sb.WriteString("- [Race Condition Attacks - OWASP](https://owasp.org/www-community/attacks/Race_condition_attack)\n")
	sb.WriteString("- [Web Cache Poisoning - PortSwigger](https://portswigger.net/research/web-cache-poisoning)\n")
	sb.WriteString("- [Smashing the state machine - PortSwigger](https://portswigger.net/research/smashing-the-state-machine)\n")

	return sb.String()
}
