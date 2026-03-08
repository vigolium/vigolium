package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// OnfocusAutofocusStrategy implements the ContextualXSSTechnique interface.
// Original Java class: ga_ (renamed to OnfocusAutofocusStrategy for Go convention)
type OnfocusAutofocusStrategy struct {
	prefix           string // Corresponds to 'a' (var1) in Java
	randomComponent1 string // Corresponds to 'd' (var2) in Java
	attributeSpacing string // Corresponds to 'c' (var3) in Java
	quoteChar        string // Corresponds to 'e' (var4) in Java
	useAdvancedMode  bool   // Corresponds to 'b' (var5) in Java
}

// NewOnfocusAutofocusStrategy creates a new instance of Ga.
// Original Java constructor: public ga_(String var1, String var2, String var3, String var4, boolean var5)
func NewOnfocusAutofocusStrategy(
	prefix, rndComp1, attrSpacing, quote string,
	advancedMode bool,
) *OnfocusAutofocusStrategy {
	return &OnfocusAutofocusStrategy{
		prefix:           prefix,
		randomComponent1: rndComp1,
		attributeSpacing: attrSpacing,
		quoteChar:        quote,
		useAdvancedMode:  advancedMode,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Ga.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *OnfocusAutofocusStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// String var7 = this.a
	//    + "#{random_string_5}"
	//    + this.d
	//    + this.c
	//    + "onfocus="
	//    + this.e
	//    + "#{poc}"
	//    + this.e
	//    + this.c
	//    + "autofocus="
	//    + this.e
	//    + this.c
	//    + "#{random_string_5b}";

	formattedPayload := receiver.prefix + // this.a
		"#{random_string_5}" +
		receiver.randomComponent1 + // this.d
		receiver.attributeSpacing + // this.c
		"onfocus=" +
		receiver.quoteChar + // this.e
		"#{poc}" +
		receiver.quoteChar + // this.e
		receiver.attributeSpacing + // this.c
		"autofocus=" +
		receiver.quoteChar + // this.e
		receiver.attributeSpacing + // this.c
		"#{random_string_5b}"

	finalProfile := profile.WithAdditionalMatchCriterion(NewAttributeValueEventMatcher(contextType, "onfocus")).
		WithAdvancedMode(receiver.useAdvancedMode)
	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
