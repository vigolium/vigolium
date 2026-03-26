package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// It implements the ScanExecutionProfile interface.
type ScanExecutionProfile struct {
	targetReflectionContext     ReflectionContext
	isAdvancedModeEnabled       bool
	requiresDetectorValidation  bool
	matchCriteria               []ReflectionMatchCriterion
	payloadTemplateData         *PayloadGenerationTemplate
	baseCanaryComponent         string
	variantCanaryComponent      string
	isHtmlEntityDecodingEnabled bool
}

// --- Constructors ---

// NewScanExecutionProfile creates a new profile for the given target context.
func NewScanExecutionProfile(targetContext ReflectionContext) *ScanExecutionProfile {
	defaultMatchCriteria := []ReflectionMatchCriterion{
		NewContextSpecificReflectionMatcher(targetContext),
	}
	return newScanExecutionProfileInternal(
		targetContext,
		false,
		false,
		defaultMatchCriteria,
		nil,
		"",
		"",
		false,
	)
}

// --- Interface Implementation ---

// This is part of the ScanExecutionProfile interface.
func (profile *ScanExecutionProfile) WithAdvancedMode(enabled bool) *ScanExecutionProfile {
	return newScanExecutionProfileInternal(
		profile.targetReflectionContext,
		enabled,
		profile.requiresDetectorValidation,
		profile.matchCriteria,
		profile.payloadTemplateData,
		profile.baseCanaryComponent,
		profile.variantCanaryComponent,
		profile.isHtmlEntityDecodingEnabled,
	)
}

// WithDetectorValidation returns a copy with detector validation enabled
// This is part of the ScanExecutionProfile interface.
func (profile *ScanExecutionProfile) WithDetectorValidation() *ScanExecutionProfile {
	return newScanExecutionProfileInternal(
		profile.targetReflectionContext,
		profile.isAdvancedModeEnabled,
		true,
		profile.matchCriteria,
		profile.payloadTemplateData,
		profile.baseCanaryComponent,
		profile.variantCanaryComponent,
		profile.isHtmlEntityDecodingEnabled,
	)
}

// This is part of the ScanExecutionProfile interface.
func (profile *ScanExecutionProfile) WithAdditionalMatchCriterion(
	criterion ReflectionMatchCriterion,
) *ScanExecutionProfile {
	updatedCriteria := make(
		[]ReflectionMatchCriterion,
		len(profile.matchCriteria),
		len(profile.matchCriteria)+1,
	)
	copy(updatedCriteria, profile.matchCriteria)
	updatedCriteria = append(updatedCriteria, criterion)
	// For unmodifiable, Go relies on convention or returning copies. Here, a new slice is created.
	return newScanExecutionProfileInternal(
		profile.targetReflectionContext,
		profile.isAdvancedModeEnabled,
		profile.requiresDetectorValidation,
		updatedCriteria,
		profile.payloadTemplateData,
		profile.baseCanaryComponent,
		profile.variantCanaryComponent,
		profile.isHtmlEntityDecodingEnabled,
	)
}

// This is part of the ScanExecutionProfile interface.
func (profile *ScanExecutionProfile) WithVariantCanaryComponent(
	component string,
) *ScanExecutionProfile {
	return newScanExecutionProfileInternal(
		profile.targetReflectionContext,
		profile.isAdvancedModeEnabled,
		profile.requiresDetectorValidation,
		profile.matchCriteria,
		profile.payloadTemplateData,
		profile.baseCanaryComponent,
		component,
		profile.isHtmlEntityDecodingEnabled,
	)
}

// WithHtmlEntityDecoding returns a copy with HTML entity decoding enabled.
func (profile *ScanExecutionProfile) WithHtmlEntityDecoding() *ScanExecutionProfile {
	return newScanExecutionProfileInternal(
		profile.targetReflectionContext,
		profile.isAdvancedModeEnabled,
		profile.requiresDetectorValidation,
		profile.matchCriteria,
		profile.payloadTemplateData,
		profile.baseCanaryComponent,
		profile.variantCanaryComponent,
		true,
	)
}

// newScanExecutionProfileInternal is the private constructor for creating ScanExecutionProfile instances.
func newScanExecutionProfileInternal(
	targetContext ReflectionContext,
	isAdvancedMode bool,
	requiresValidation bool,
	initialCriteria []ReflectionMatchCriterion,
	templateData *PayloadGenerationTemplate,
	baseCanary string,
	variantCanary string,
	enableDecoding bool,
) *ScanExecutionProfile {
	// Defensive copy for dVal to ensure immutability if the caller modifies the slice later
	criteriaCopy := make([]ReflectionMatchCriterion, len(initialCriteria))
	copy(criteriaCopy, initialCriteria)

	return &ScanExecutionProfile{
		targetReflectionContext:     targetContext,
		isAdvancedModeEnabled:       isAdvancedMode,
		requiresDetectorValidation:  requiresValidation,
		matchCriteria:               criteriaCopy, // Use the copied slice
		payloadTemplateData:         templateData,
		baseCanaryComponent:         baseCanary,
		variantCanaryComponent:      variantCanary,
		isHtmlEntityDecodingEnabled: enableDecoding,
	}
}

// GetPayloadTemplateData returns the payload generation template data.
func (profile *ScanExecutionProfile) GetPayloadTemplateData() *PayloadGenerationTemplate {
	return profile.payloadTemplateData
}

// Renamed to avoid conflict with interface method A(), and to show it's for internal chaining.
func (profile *ScanExecutionProfile) withPayloadTemplateData(
	templateData *PayloadGenerationTemplate,
) *ScanExecutionProfile {
	return newScanExecutionProfileInternal(
		profile.targetReflectionContext,
		profile.isAdvancedModeEnabled,
		profile.requiresDetectorValidation,
		profile.matchCriteria,
		templateData,
		profile.baseCanaryComponent,
		profile.variantCanaryComponent,
		profile.isHtmlEntityDecodingEnabled,
	)
}

// Renamed to avoid conflict and indicate internal use.
func (profile *ScanExecutionProfile) withBaseCanaryComponent(fStr string) *ScanExecutionProfile {
	return newScanExecutionProfileInternal(
		profile.targetReflectionContext,
		profile.isAdvancedModeEnabled,
		profile.requiresDetectorValidation,
		profile.matchCriteria,
		profile.payloadTemplateData,
		fStr,
		profile.variantCanaryComponent,
		profile.isHtmlEntityDecodingEnabled,
	)
}

// CreateMatcherWithRandomSuffix creates a search pattern by combining the profile's
// internal base payload with the provided random suffix.
func (profile *ScanExecutionProfile) CreateMatcherWithRandomSuffix(
	randomSuffix []byte,
) ByteSequenceMatcher {
	// Get the base payload part (e.g., primaryCanaryComponent)
	basePayloadComponent := profile.getEffectiveCanaryComponent()
	basePayloadBytes := utils.StringToBytes(basePayloadComponent)

	// Combine the base payload part with the random suffix
	fullPatternBytes := utils.CombineByteSlices(
		basePayloadBytes,
		randomSuffix, // This is the random suffix
	)
	return profile.createPatternMatcher(fullPatternBytes)
}

// CreateMatcherForEffectiveCanary corresponds to package-private 'db9 c()'
func (profile *ScanExecutionProfile) CreateMatcherForEffectiveCanary() ByteSequenceMatcher {
	effectiveCanaryString := profile.getEffectiveCanaryComponent()
	effectiveCanaryBytes := utils.StringToBytes(
		effectiveCanaryString,
	)
	return profile.createPatternMatcher(effectiveCanaryBytes)
}

// --- Private Helper Methods ---

// getAggregatedMatchCriterion returns a composite matcher that checks if all
// match criteria pass for a given reflection detail.
func (profile *ScanExecutionProfile) getAggregatedMatchCriterion() ReflectionMatchCriterion {
	// Return a struct that implements ReflectionMatchCriterion and checks all criteria
	return &aggregateReflectionMatcher{criteria: profile.matchCriteria}
}

// getEffectiveCanaryComponent corresponds to 'private String e()'
func (profile *ScanExecutionProfile) getEffectiveCanaryComponent() string {
	if profile.variantCanaryComponent == "" {
		return profile.baseCanaryComponent
	}
	return FormatPayloadFromTemplate(
		profile.variantCanaryComponent,
		profile.payloadTemplateData,
	)
}

func (profile *ScanExecutionProfile) createPatternMatcher(patternBytes []byte) ByteSequenceMatcher {
	if profile.isHtmlEntityDecodingEnabled {
		if profile.isAdvancedModeEnabled {
			return NewUnescapingHtmlDecodingBytePatternMatcher(patternBytes)
		} else {
			return NewHtmlDecodingBytePatternMatcher(patternBytes)
		}
	} else {
		if profile.isAdvancedModeEnabled {
			return NewUnescapingBytePatternMatcher(patternBytes)
		} else {
			return NewSimpleBytePatternMatcher(patternBytes)
		}
	}
}

/* -------------------------------------------------------------------------- */
// aggregateReflectionMatcher implements ReflectionMatchCriterion to combine multiple matchers.
type aggregateReflectionMatcher struct {
	criteria []ReflectionMatchCriterion
}

func (m *aggregateReflectionMatcher) IsReflectionMatchCriterion() {}
func (m *aggregateReflectionMatcher) Matches(reflection ReflectionOccurrenceDetail) bool {

	for _, matcher := range m.criteria {
		if !matcher.Matches(reflection) {
			return false
		}

	}
	return true
}

/* -------------------------------------------------------------------------- */

type ContextSpecificReflectionMatcher struct {
	targetContextType ReflectionContext
}

func NewContextSpecificReflectionMatcher(
	targetContext ReflectionContext,
) *ContextSpecificReflectionMatcher {
	return &ContextSpecificReflectionMatcher{
		targetContextType: targetContext,
	}
}

func (d *ContextSpecificReflectionMatcher) Matches(
	detectedReflection ReflectionOccurrenceDetail,
) bool {
	if detectedReflection == nil || detectedReflection.CoreInfo() == nil {
		return false
	}
	coreInfo := detectedReflection.CoreInfo()
	match := coreInfo.ContextType() == d.targetContextType

	return match
}
func (d *ContextSpecificReflectionMatcher) IsReflectionMatchCriterion() {}
