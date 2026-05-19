package core

import (
	"strings"
	"unicode"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// ReflectionOccurrenceDetail represents a detected reflection point in a response.
type ReflectionOccurrenceDetail interface {
	CoreInfo() *ReflectionPointCoreInfo
	GetRedirectionTarget(detector *HTTPReflectionPointDetector) *RedirectionTargetInfo
	Accept(visitor ReflectionDetailVisitor) interface{}
}

// RedirectionTargetInfo holds redirection target information for a reflection point.
type RedirectionTargetInfo struct {
	RedirectType       RedirectType
	Value              string
	OriginalMatchStart int
	OriginalMatchEnd   int
	RawContent         []byte
}

func NewRedirectDetails(
	redirectType RedirectType,
	value string,
	matchStartOffset, matchEndOffset int,
	rawContent []byte,
) *RedirectionTargetInfo {
	return &RedirectionTargetInfo{
		RedirectType:       redirectType,
		Value:              value,
		OriginalMatchStart: matchStartOffset,
		OriginalMatchEnd:   matchEndOffset,
		RawContent:         rawContent,
	}
}

type ReflectionMatchCriterion interface {
	IsReflectionMatchCriterion() // Marker method
	Matches(reflection ReflectionOccurrenceDetail) bool
}

type AttributeValueEventMatcher struct {
	targetContextType    ReflectionContext
	targetAttributeValue string
}

func NewAttributeValueEventMatcher(
	targetContext ReflectionContext,
	targetValue string,
) *AttributeValueEventMatcher {
	return &AttributeValueEventMatcher{
		targetContextType:    targetContext,
		targetAttributeValue: targetValue,
	}
}
func (matcher *AttributeValueEventMatcher) Matches(reflection ReflectionOccurrenceDetail) bool {
	return false
}
func (matcher *AttributeValueEventMatcher) IsReflectionMatchCriterion() {}

/* -------------------------------------------------------------------------- */
type AttackTechniqueClassifier interface {
	String() string
	ClassificationCode() int
}

type AttackStepRunner interface {
	RunAttackStep(
		injectionPoint httpmsg.InsertionPoint,
		scanFlags int,
		formattedPayload string,
		tactic ReflectionTacticType,
		contextCode byte,
		classifier AttackTechniqueClassifier,
		useSecondaryCanary bool,
		profile *ScanExecutionProfile,
	) PotentialXSSFinding
}

type RandomTextProvider interface {
	GenerateText(length int) string
}

type PotentialXSSFinding interface {
	IsPotentialXSSFinding() // Marker method
	ScanFlags() int
	VariantCode() byte
}

type ContextualAttackPayloadGenerator interface {
	GeneratePayload(
		probeBuilder *ScanProbeBuilder,
		profile *ScanExecutionProfile,
		tactic ReflectionTacticType,
		contextType ReflectionContext,
		reflection ReflectionOccurrenceDetail,
		transaction *utils.HTTPTransaction,
	) PotentialXSSFinding
}

/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */

func mangleTagNameForClosing(tagName string) string {
	var mangledNameBuilder strings.Builder
	mangledNameBuilder.Grow(len(tagName)) // Pre-allocate capacity for efficiency

	for i, character := range tagName {
		if i%2 == 1 {
			// If index is odd, append the character as is
			mangledNameBuilder.WriteRune(character)
		} else {
			// If index is even
			if unicode.IsUpper(character) {
				// If the character is uppercase, convert to lowercase
				mangledNameBuilder.WriteRune(unicode.ToLower(character))
			} else {
				// Otherwise (lowercase or not a letter), convert to uppercase
				mangledNameBuilder.WriteRune(unicode.ToUpper(character))
			}
		}
	}
	return mangledNameBuilder.String()
}

/* -------------------------------------------------------------------------- */
type JavaScriptPayloadParams struct {
	primaryComponent string
	encodedComponent string
	flag             int
}

/* -------------------------------------------------------------------------- */
type SchemeDefinition interface {
	IsSchemeDefinition()
	SchemeFlag() int
	SchemeName() string
}

type BasicSchemeDefinition struct {
	schemeNameValue string
}

func NewBasicSchemeDefinition(
	schemeNameValue string,
) SchemeDefinition {
	stub := &BasicSchemeDefinition{schemeNameValue: schemeNameValue}
	return stub
}
func (s *BasicSchemeDefinition) IsSchemeDefinition() {}
func (s *BasicSchemeDefinition) SchemeName() string  { return s.schemeNameValue }
func (s *BasicSchemeDefinition) SchemeFlag() int     { return 0 }

type MixCasesSchemeDefinition struct{ schemeNameValue string }

func NewMixCasesSchemeDefinition(schemeNameValue string) SchemeDefinition {
	stub := &MixCasesSchemeDefinition{schemeNameValue: schemeNameValue}
	return stub
}
func (s *MixCasesSchemeDefinition) IsSchemeDefinition() {}
func (s *MixCasesSchemeDefinition) SchemeName() string  { return s.schemeNameValue }
func (s *MixCasesSchemeDefinition) SchemeFlag() int     { return 8 }

/* -------------------------------------------------------------------------- */
type StrategyGeneratorFromString interface {
	CreateStrategy(terminatorVariant string) ContextualAttackPayloadGenerator
}
type StrategyGeneratorFromOperator interface {
	CreateStrategy(operator string) ContextualAttackPayloadGenerator
}

/* -------------------------------------------------------------------------- */

type ScanExecutionManager interface {
	Scan(
		injectionPoint httpmsg.InsertionPoint,
		currentScanFlags int,
		basePayload []byte,
		tactic ReflectionTacticType,
		targetContextForProfile ReflectionContext,
		detector *HTTPReflectionPointDetector,
		needsFollowUpRequest bool,
		profile *ScanExecutionProfile,
	) PotentialXSSFinding
}
