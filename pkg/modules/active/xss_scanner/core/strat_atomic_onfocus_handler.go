package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// OnfocusEventHandlerStrategy implements the ContextualXSSTechnique interface.
// Original Java class: ec1
type OnfocusEventHandlerStrategy struct {
	prefix                    string // Corresponds to 'd' in Java
	randomComponent1          string // Corresponds to 'a' in Java
	attributeSpacingAndTagEnd string // Corresponds to 'e' in Java
	quoteChar                 string // Corresponds to 'c' in Java
	useAdvancedMode           bool   // Corresponds to 'b' in Java
}

// NewOnfocusEventHandlerStrategy creates a new instance of Ec1.
// Original Java constructor: public ec1(String var1, String var2, String var3, String var4, boolean var5)
func NewOnfocusEventHandlerStrategy(
	prefix, rndComp1, attrSpacingTagEnd, quote string,
	advancedMode bool,
) *OnfocusEventHandlerStrategy {
	return &OnfocusEventHandlerStrategy{
		prefix:                    prefix,            // map to d
		randomComponent1:          rndComp1,          // map to a
		attributeSpacingAndTagEnd: attrSpacingTagEnd, // map to e
		quoteChar:                 quote,             // map to c
		useAdvancedMode:           advancedMode,      // map to b
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *OnfocusEventHandlerStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic for formattedPayload string:
	// this.d + "#{random_string_5}" + this.a + this.e + "onfocus=" + this.c + "#{poc}" + this.c + this.e + "#{random_string_5b}"
	formattedPayload := receiver.prefix + "#{random_string_5}" + receiver.randomComponent1 + receiver.attributeSpacingAndTagEnd +
		"onfocus=" + receiver.quoteChar + "#{poc}" + receiver.quoteChar + receiver.attributeSpacingAndTagEnd +
		"#{random_string_5b}"

	// Hnx methods now return Hnx for chaining.
	finalProfile := profile.WithAdditionalMatchCriterion(NewAttributeValueEventMatcher(contextType, "onfocus")).
		WithAdvancedMode(receiver.useAdvancedMode)

	// Call BuildBgf on Hgm
	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
