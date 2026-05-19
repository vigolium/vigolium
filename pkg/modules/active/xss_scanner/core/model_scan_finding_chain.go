package core

import (
	"fmt"
)

// Severity levels for XSS findings
const (
	FindingSeverityUnknown = 0 // Unknown or not set
	FindingSeverityLow     = 1 // Character injection (", ', `, <, >, etc)
	FindingSeverityMedium  = 2 // Context breakout/control (tag close, attribute manipulation)
	FindingSeverityHigh    = 3 // Full POC execution (alert, prompt, script execution)
)

// ChainedXSSFinding represents a sequence of successful injection steps
// and shows the complete attack progression even when final POC fails.
type ChainedXSSFinding struct {
	URL                string
	Parameter          string
	ReflectionContext  ReflectionContext
	ReflectionTactic   ReflectionTacticType
	ReflectionLocation ReflectionLocation

	// The chain of findings (both successful and failed steps)
	Steps []*FindingStep

	// Summary metrics
	TotalSteps         int
	SuccessfulSteps    int
	MaxSeverityReached int
	StoppedAtStep      int // Where chain broke (0 = completed all steps)

	// Raw HTTP data (copied from last successful finding)
	RequestRaw         []byte
	ResponseBody       []byte
	ResponseStatusCode int
	ContentType        string
}

// FindingStep represents one step in the exploitation chain
type FindingStep struct {
	Index    int
	Success  bool
	Severity int // FindingSeverityLow/Medium/High

	// For successful steps
	Finding       *XSSScanFinding // Full finding details
	TechniqueName string          // "Character Injection", "Event Handler", etc
	Evidence      string          // What was successfully injected

	// For failed steps
	StrategyName   string // Strategy that was attempted
	FailureReason  string // Why it failed
	AttemptedCount int    // How many alternatives tried (for iterators)
}

// IsPotentialXSSFinding marker method for PotentialXSSFinding interface
func (c *ChainedXSSFinding) IsPotentialXSSFinding() {}

// Severity returns the highest severity reached in the chain
func (c *ChainedXSSFinding) Severity() int {
	return c.MaxSeverityReached
}

// ScanFlags returns combined flags from all successful steps
func (c *ChainedXSSFinding) ScanFlags() int {
	combinedFlags := 0
	for _, step := range c.Steps {
		if step.Success && step.Finding != nil {
			combinedFlags |= step.Finding.ScanFlags()
		}
	}
	return combinedFlags
}

// VariantCode returns the variant from the last successful finding
func (c *ChainedXSSFinding) VariantCode() byte {
	for i := len(c.Steps) - 1; i >= 0; i-- {
		if c.Steps[i].Success && c.Steps[i].Finding != nil {
			return c.Steps[i].Finding.VariantCode()
		}
	}
	return 0
}

// GetEvidenceSummary returns a formatted multi-line summary of the chain
func (c *ChainedXSSFinding) GetEvidenceSummary() string {
	if len(c.Steps) == 0 {
		return "No steps in chain"
	}

	summary := fmt.Sprintf("XSS Chain: %d/%d steps successful (max severity: %s)\n",
		c.SuccessfulSteps, c.TotalSteps, SeverityLabel(c.MaxSeverityReached))

	for _, step := range c.Steps {
		if step.Success {
			summary += fmt.Sprintf("  ✓ Step %d [%s]: %s\n",
				step.Index+1, SeverityLabel(step.Severity), step.TechniqueName)
			if step.Evidence != "" {
				summary += fmt.Sprintf("      Evidence: %s\n", step.Evidence)
			}
		} else {
			summary += fmt.Sprintf("  ✗ Step %d: %s (blocked)\n",
				step.Index+1, step.StrategyName)
			if step.FailureReason != "" {
				summary += fmt.Sprintf("      Reason: %s\n", step.FailureReason)
			}
		}
	}

	if c.StoppedAtStep > 0 && c.SuccessfulSteps > 0 {
		summary += fmt.Sprintf("\nNote: Chain stopped at step %d - manual exploitation may be possible\n", c.StoppedAtStep+1)
	}

	return summary
}

// GetResponseBody returns the response body from the last successful finding
func (c *ChainedXSSFinding) GetResponseBody() []byte {
	return c.ResponseBody
}

// GetRequestRaw returns the raw request from the last successful finding
func (c *ChainedXSSFinding) GetRequestRaw() []byte {
	return c.RequestRaw
}

// GetResponseStatusCode returns the status code from the last successful finding
func (c *ChainedXSSFinding) GetResponseStatusCode() int {
	return c.ResponseStatusCode
}

// GetContentType returns the content type from the last successful finding
func (c *ChainedXSSFinding) GetContentType() string {
	return c.ContentType
}

// SeverityLabel returns a human-readable label for a severity level
func SeverityLabel(severity int) string {
	switch severity {
	case FindingSeverityLow:
		return "LOW"
	case FindingSeverityMedium:
		return "MEDIUM"
	case FindingSeverityHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// BuildChainedFinding creates a ChainedXSSFinding from a sequence of steps
func BuildChainedFinding(
	steps []*FindingStep,
	contextType ReflectionContext,
	tactic ReflectionTacticType,
) *ChainedXSSFinding {
	if len(steps) == 0 {
		return nil
	}

	// Calculate metrics
	successCount := 0
	maxSeverity := FindingSeverityUnknown
	stoppedAt := 0
	var lastSuccessfulFinding *XSSScanFinding

	for i, step := range steps {
		if step.Success {
			successCount++
			if step.Severity > maxSeverity {
				maxSeverity = step.Severity
			}
			if step.Finding != nil {
				lastSuccessfulFinding = step.Finding
			}
		} else {
			if stoppedAt == 0 {
				stoppedAt = i
			}
		}
	}

	if successCount == 0 {
		return nil
	}

	chainedFinding := &ChainedXSSFinding{
		Steps:              steps,
		TotalSteps:         len(steps),
		SuccessfulSteps:    successCount,
		MaxSeverityReached: maxSeverity,
		StoppedAtStep:      stoppedAt,
		ReflectionContext:  contextType,
		ReflectionTactic:   tactic,
	}

	// Copy metadata from last successful finding
	if lastSuccessfulFinding != nil {
		chainedFinding.URL = lastSuccessfulFinding.URL
		chainedFinding.ReflectionLocation = lastSuccessfulFinding.ReflectionLocation
		chainedFinding.RequestRaw = lastSuccessfulFinding.RequestRaw
		chainedFinding.ResponseBody = lastSuccessfulFinding.ResponseBody
		chainedFinding.ResponseStatusCode = lastSuccessfulFinding.ResponseStatusCode
		chainedFinding.ContentType = lastSuccessfulFinding.ContentType

		// Extract parameter name from InjectionPoint
		if lastSuccessfulFinding.InjectionPoint != nil {
			chainedFinding.Parameter = lastSuccessfulFinding.InjectionPoint.Name()
		}
	}

	return chainedFinding
}

// GetStrategyName returns a human-readable name for a strategy
func GetStrategyName(strategy ContextualAttackPayloadGenerator) string {
	if strategy == nil {
		return "UnknownStrategy"
	}

	// Get type name
	typeName := fmt.Sprintf("%T", strategy)

	// Extract just the struct name (remove package path)
	if idx := lastIndexByte(typeName, '.'); idx >= 0 && idx < len(typeName)-1 {
		typeName = typeName[idx+1:]
	}

	// Remove common suffixes for cleaner names
	typeName = trimSuffix(typeName, "Strategy")
	typeName = trimSuffix(typeName, "Wrapper")
	typeName = trimSuffix(typeName, "Adapter")

	return typeName
}

// Helper function to find last occurrence of a byte in string
func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// Helper function to trim suffix from string
func trimSuffix(s, suffix string) string {
	if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)]
	}
	return s
}

// ExtractInjectionEvidence extracts the key characters/pattern that were successfully injected
func ExtractInjectionEvidence(payload []byte, reflectionInfo *ReflectionPointCoreInfo) string {
	if reflectionInfo == nil || len(reflectionInfo.canaryBytes) == 0 {
		return string(payload)
	}

	// Return the canary that was successfully reflected
	evidence := string(reflectionInfo.canaryBytes)

	// Limit evidence length for readability
	if len(evidence) > 100 {
		evidence = evidence[:97] + "..."
	}

	return evidence
}

// InferSeverityFromStrategy infers severity level based on strategy type name.
// This centralizes severity classification so we don't need to modify 33+ atomic strategies.
func InferSeverityFromStrategy(strategy ContextualAttackPayloadGenerator) int {
	if strategy == nil {
		return FindingSeverityUnknown
	}

	strategyName := GetStrategyName(strategy)

	// HIGH: Code execution strategies (event handlers, script tags, function calls)
	if containsAny(strategyName, []string{
		"Handler", "ScriptTag", "SimpleCall", "Onerror", "Onclick",
		"Onfocus", "Onload", "Onmouseover", "Autofocus", "DataURI",
	}) {
		return FindingSeverityHigh
	}

	// MEDIUM: Context breakout and control (tag manipulation, attribute control)
	if containsAny(strategyName, []string{
		"TagBreakout", "ClosingTag", "AttributeInjection", "AttributeEvent",
		"InvalidTag", "CommentCloser", "Anchor", "SimpleAttribute",
	}) {
		return FindingSeverityMedium
	}

	// LOW: Character injection and basic syntax breaking
	if containsAny(strategyName, []string{
		"CharInjection", "CharacterInjection", "SemicolonInjection",
		"StringConstructor", "QuotedAttribute", "JSString",
	}) {
		return FindingSeverityLow
	}

	// Default: Unknown severity
	return FindingSeverityUnknown
}

// InferTechniqueNameFromStrategy generates a human-readable technique name from strategy type.
func InferTechniqueNameFromStrategy(strategy ContextualAttackPayloadGenerator) string {
	if strategy == nil {
		return "Unknown Technique"
	}

	strategyName := GetStrategyName(strategy)

	// Remove common suffixes
	name := strategyName
	name = trimSuffix(name, "Strategy")
	name = trimSuffix(name, "Composite")
	name = trimSuffix(name, "Meta")
	name = trimSuffix(name, "Wrapper")

	// Convert CamelCase to readable format
	readable := splitCamelCase(name)

	return readable
}

// splitCamelCase converts CamelCase to space-separated words
// e.g., "SingleCharacterInjection" -> "Single Character Injection"
func splitCamelCase(s string) string {
	if s == "" {
		return s
	}

	var result []rune
	var prev rune

	for i, curr := range s {
		// Add space before uppercase letter if:
		// - Not at start
		// - Previous char was lowercase or digit
		if i > 0 && isUpper(curr) && (isLower(prev) || isDigit(prev)) {
			result = append(result, ' ')
		}
		result = append(result, curr)
		prev = curr
	}

	return string(result)
}

// Helper functions for character classification
func isUpper(r rune) bool {
	return r >= 'A' && r <= 'Z'
}

func isLower(r rune) bool {
	return r >= 'a' && r <= 'z'
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

// containsAny checks if string contains any of the substrings
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
