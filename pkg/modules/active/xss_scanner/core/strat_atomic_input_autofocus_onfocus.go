package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// InputTextAutofocusOnfocusStrategy implements the ContextualXSSTechnique interface.
// Original Java class: cb4
type InputTextAutofocusOnfocusStrategy struct {
	prefix           string // Corresponds to 'e' in Java
	randomComponent1 string // Corresponds to 'd' in Java
	attributeSpacing string // Corresponds to 'c' in Java
	quoteChar        string // Corresponds to 'b' in Java
	useAdvancedMode  bool   // Corresponds to 'a' in Java
}

// NewInputTextAutofocusOnfocusStrategy creates a new instance of Cb4.
// Original Java constructor: public cb4(String var1, String var2, String var3, String var4, boolean var5)
func NewInputTextAutofocusOnfocusStrategy(
	prefix, randomComponent1, attributeSpacing, quoteChar string,
	useAdvancedMode bool,
) *InputTextAutofocusOnfocusStrategy {
	return &InputTextAutofocusOnfocusStrategy{
		prefix:           prefix,           // map to e
		randomComponent1: randomComponent1, // map to d
		attributeSpacing: attributeSpacing, // map to c
		quoteChar:        quoteChar,        // map to b
		useAdvancedMode:  useAdvancedMode,  // map to a
	}
}

// getFocusAttributeSpacing is the Go equivalent of the private Java method a()
//
//	private String a() {
//	   return this.c != null && !this.c.isEmpty() ? this.c : " ";
//	}
func (receiver *InputTextAutofocusOnfocusStrategy) getFocusAttributeSpacing() string {
	// In Go, string cannot be null. So, this.c != null is implicit if ValC is string.
	// !this.c.isEmpty() translates to receiver.ValC != ""
	if receiver.attributeSpacing != "" {
		return receiver.attributeSpacing
	}
	return " "
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *InputTextAutofocusOnfocusStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic for payload string (var7):
	// String var7 = this.e
	//    + "#{random_string_5}"
	//    + this.d
	//    + this.c
	//    + "type="
	//    + this.b
	//    + "text"
	//    + this.b
	//    + this.c
	//    + "autofocus"
	//    + this.a() // Calls private method
	//    + "onfocus="
	//    + this.b
	//    + "#{poc}"
	//    + this.b
	//    + "//#{random_string_5b}";

	formattedPayload := receiver.prefix + // this.e
		"#{random_string_5}" +
		receiver.randomComponent1 + // this.d
		receiver.attributeSpacing + // this.c
		"type=" +
		receiver.quoteChar + // this.b
		"text" +
		receiver.quoteChar + // this.b
		receiver.attributeSpacing + // this.c
		"autofocus" +
		receiver.getFocusAttributeSpacing() + // this.a()
		"onfocus=" +
		receiver.quoteChar + // this.b
		"#{poc}" +
		receiver.quoteChar + // this.b
		"//#{random_string_5b}"

	// Hnx processing: var2.a(new dp_(var4)).a(this.a)
	finalProfile := profile.WithAdditionalMatchCriterion(NewContextSpecificReflectionMatcher(contextType)).
		WithAdvancedMode(receiver.useAdvancedMode)

	// Final return: var1.a(36).a((byte)2, var7, hnxResult);
	return probeBuilder.WithAdditionalScanFlags(36).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
