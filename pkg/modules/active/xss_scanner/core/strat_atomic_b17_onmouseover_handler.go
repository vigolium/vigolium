package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// BasicOnmouseoverStrategy implements the ContextualXSSTechnique interface.
// Original Java class: b17
type BasicOnmouseoverStrategy struct {
	prefix                    string // Corresponds to 'd' in Java
	randomComponent           string // Corresponds to 'e' in Java
	attributeSpacingAndTagEnd string // Corresponds to 'a' in Java
	quoteChar                 string // Corresponds to 'c' in Java
	useAdvancedMode           bool   // Corresponds to 'b' in Java
}

// NewBasicOnmouseoverStrategy creates a new instance of B17.
// Original Java constructor: public b17(String var1, String var2, String var3, String var4, boolean var5)
func NewBasicOnmouseoverStrategy(
	prefix, randomComp, attrSpaceTagEnd, quote string,
	advancedMode bool,
) *BasicOnmouseoverStrategy {
	return &BasicOnmouseoverStrategy{
		prefix:                    prefix,          // map to d
		randomComponent:           randomComp,      // map to e
		attributeSpacingAndTagEnd: attrSpaceTagEnd, // map to a
		quoteChar:                 quote,           // map to c
		useAdvancedMode:           advancedMode,    // map to b
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *BasicOnmouseoverStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic for formattedPayload string:
	// this.d + "#{random_string_5}" + this.e + this.a + "onmouseover=" + this.c + "#{poc}" + this.c + this.a + "#{random_string_5b}"
	formattedPayload := receiver.prefix + "#{random_string_5}" + receiver.randomComponent + receiver.attributeSpacingAndTagEnd +
		"onmouseover=" + receiver.quoteChar + "#{poc}" + receiver.quoteChar + receiver.attributeSpacingAndTagEnd +
		"#{random_string_5b}"

	// Hnx methods now return Hnx for chaining.
	finalProfile := profile.WithAdditionalMatchCriterion(NewAttributeValueEventMatcher(contextType, "onmouseover")).
		WithAdvancedMode(receiver.useAdvancedMode)

	// Call BuildBgf on Hgm
	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
