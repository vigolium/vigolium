package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ScanExecutionProfile is the Go equivalent of the Java class hnx.
// It implements the ScanExecutionProfile interface.
type ScanExecutionProfile struct {
	targetReflectionContext     ReflectionContext          // Corresponds to 'private final byte g;'
	isAdvancedModeEnabled       bool                       // Corresponds to 'public final boolean e;' - made public for direct access if needed
	requiresDetectorValidation  bool                       // Corresponds to 'final boolean a;' - made public for direct access if needed
	matchCriteria               []ReflectionMatchCriterion // Corresponds to 'private final Collection<e7s> d;' - using a slice
	payloadTemplateData         *PayloadGenerationTemplate // Corresponds to 'private final glw c;'
	baseCanaryComponent         string                     // Corresponds to 'private final String f;'
	variantCanaryComponent      string                     // Corresponds to 'private final String b;'
	isHtmlEntityDecodingEnabled bool                       // Corresponds to 'private final boolean h;'
}

// --- Constructors ---

// NewScanExecutionProfile is the public constructor, corresponds to 'public hnx(byte var1)'.
// It returns Hnx interface type.
func NewScanExecutionProfile(targetContext ReflectionContext) *ScanExecutionProfile {
	// In Java: this(var1, false, false, Collections.unmodifiableCollection(Collections.singletonList(new dp_(var1))), null, null, null, false);
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

// WithAdvancedMode corresponds to 'public hnx a(boolean var1)'
// This is part of the Hnx interface in stubs.go
func (profile *ScanExecutionProfile) WithAdvancedMode(enabled bool) *ScanExecutionProfile {
	// return new hnx(this.g, var1, this.a, this.d, this.c, this.f, this.b, this.h);
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

// WithDetectorValidation corresponds to 'public hnx f()'
// This is part of the Hnx interface in stubs.go
func (profile *ScanExecutionProfile) WithDetectorValidation() *ScanExecutionProfile {
	// return new hnx(this.g, this.e, true, this.d, this.c, this.f, this.b, this.h);
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

// WithAdditionalMatchCriterion corresponds to 'public hnx a(e7s var1)'
// This is part of the Hnx interface in stubs.go
func (profile *ScanExecutionProfile) WithAdditionalMatchCriterion(
	criterion ReflectionMatchCriterion,
) *ScanExecutionProfile {
	// ArrayList var2 = new ArrayList<>(this.d);
	// var2.add(var1);
	// return new hnx(this.g, this.e, this.a, Collections.unmodifiableCollection(var2), this.c, this.f, this.b, this.h);
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

// WithVariantCanaryComponent corresponds to 'public hnx b(String var1)'
// This is part of the Hnx interface in stubs.go
func (profile *ScanExecutionProfile) WithVariantCanaryComponent(
	component string,
) *ScanExecutionProfile {
	// return new hnx(this.g, this.e, this.a, this.d, this.c, this.f, var1, this.h);
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

// WithHtmlEntityDecoding corresponds to 'public hnx a()'
// This is part of the Hnx interface in stubs.go
func (profile *ScanExecutionProfile) WithHtmlEntityDecoding() *ScanExecutionProfile {
	// return new hnx(this.g, this.e, this.a, this.d, this.c, this.f, this.b, true);
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

// newScanExecutionProfileInternal is the private constructor equivalent for creating Hnx instances.
// Corresponds to 'private hnx(byte var1, boolean var2, boolean var3, Collection<e7s> var4, glw var5, String var6, String var7, boolean var8)'
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

// --- Other Public/Package-Private Methods (Not part of Hnx interface but part of hnx.java functionality) ---

// GetPayloadTemplateData corresponds to 'public glw b()'
func (profile *ScanExecutionProfile) GetPayloadTemplateData() *PayloadGenerationTemplate {
	return profile.payloadTemplateData
}

// withPayloadTemplateData corresponds to package-private 'hnx a(glw var1)'
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

// withBaseCanaryComponent corresponds to package-private 'hnx a(String var1)'
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

// CreateMatcherWithRandomSuffix corresponds to Java's package-private 'db9 b(byte[] var1_randomSuffix)'.
// It creates a search pattern by combining the Hnx's internal base payload (from eInternal)
// with the provided random suffix.
func (profile *ScanExecutionProfile) CreateMatcherWithRandomSuffix(
	randomSuffix []byte,
) ByteSequenceMatcher {
	// Get the base payload part (e.g., primaryCanaryComponent)
	basePayloadComponent := profile.getEffectiveCanaryComponent()
	basePayloadBytes := utils.StringToBytes(basePayloadComponent)

	// Combine the base payload part with the random suffix
	fullPatternBytes := utils.NetPortswiggerNkCombine(
		basePayloadBytes,
		randomSuffix, // This is the random suffix
	)
	return profile.createPatternMatcher(fullPatternBytes)
}

// CreateMatcherForEffectiveCanary corresponds to package-private 'db9 c()'
func (profile *ScanExecutionProfile) CreateMatcherForEffectiveCanary() ByteSequenceMatcher {
	// return this.a(net.portswigger.h9.a(this.e()));
	effectiveCanaryString := profile.getEffectiveCanaryComponent()
	effectiveCanaryBytes := utils.StringToBytes(
		effectiveCanaryString,
	)
	return profile.createPatternMatcher(effectiveCanaryBytes)
}

// --- Private Helper Methods ---

// getAggregatedMatchCriterion corresponds to 'e7s d()' which returns the lambda.
// The lambda checks if all E7s matchers in the internal list 'd' pass for a given Eqx.
func (profile *ScanExecutionProfile) getAggregatedMatchCriterion() ReflectionMatchCriterion {
	// return this::lambda$aggregateReflectionMatchers$0;
	// In Go, we can return a struct that implements E7s and captures 'h.valD'
	return &aggregateReflectionMatcher{criteria: profile.matchCriteria}
}

// getEffectiveCanaryComponent corresponds to 'private String e()'
func (profile *ScanExecutionProfile) getEffectiveCanaryComponent() string {
	// return this.b == null ? this.f : hgm.a(this.b, this.c);
	// In Go, string zero value is "". Java null check becomes empty string check.
	if profile.variantCanaryComponent == "" {
		return profile.baseCanaryComponent
	}
	return FormatPayloadFromTemplate(
		profile.variantCanaryComponent,
		profile.payloadTemplateData,
	) // Static call to hgm.a(String, glw), from hgm.go or stubs
}

// createPatternMatcher corresponds to 'private db9 a(byte[] var1)'
func (profile *ScanExecutionProfile) createPatternMatcher(patternBytes []byte) ByteSequenceMatcher {
	// if (this.h) {
	//    return this.e ? e8u.b(var1) : e8u.d(var1);
	// } else {
	//    return this.e ? e8u.c(var1) : e8u.a(var1);
	// }
	// E8u methods are from stubs.go
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
// aggregateReflectionMatcher implements E7s to combine multiple matchers.
// This replaces the Java lambda this::lambda$aggregateReflectionMatchers$0
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
	hpo := detectedReflection.CoreInfo()
	match := hpo.ContextType() == d.targetContextType

	return match
}
func (d *ContextSpecificReflectionMatcher) IsReflectionMatchCriterion() {}
