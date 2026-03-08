package race_interference

import (
	"fmt"
	"strings"
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

// buildDescription generates a markdown description for the finding.
func (f *Finding) buildDescription() string {
	var sb strings.Builder

	switch f.Type {
	case FindingInputStorage:
		sb.WriteString("**Input Storage Detected**\n\n")
		sb.WriteString("The application stores user input from URL parameters and includes it in subsequent responses. ")
		sb.WriteString("This may indicate cache poisoning vulnerabilities where attacker-controlled data ")
		sb.WriteString("is served to other users.\n\n")
		sb.WriteString("### Impact\n")
		sb.WriteString("- Cache poisoning: Malicious content served to other users\n")
		sb.WriteString("- Stored XSS: If input is reflected without sanitization\n")
		sb.WriteString("- Session confusion: User data leaked to other sessions\n")

	case FindingCrossContamination:
		sb.WriteString("**Cross-contamination Race Condition Detected**\n\n")
		sb.WriteString("When parallel requests are sent, data from one request appears in the response ")
		sb.WriteString("of another request. This indicates unsafe shared state between concurrent requests.\n\n")
		sb.WriteString("### Impact\n")
		sb.WriteString("- Information disclosure: Data leaks between user sessions\n")
		sb.WriteString("- Authentication bypass: Session tokens may leak\n")
		sb.WriteString("- Data integrity: User data may be corrupted\n")

	case FindingRequestInterference:
		sb.WriteString("**Request Interference Race Condition Detected**\n\n")
		sb.WriteString("Parallel requests cause divergent responses compared to sequential baseline. ")
		sb.WriteString("This indicates the application has race condition vulnerabilities ")
		sb.WriteString("where concurrent access to shared resources causes unpredictable behavior.\n\n")
		sb.WriteString("### Impact\n")
		sb.WriteString("- TOCTOU vulnerabilities: Check-then-act operations may be exploited\n")
		sb.WriteString("- Business logic bypass: Race conditions in payment/inventory systems\n")
		sb.WriteString("- Privilege escalation: Role changes may not be atomic\n")
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
