package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// StyledOnmouseoverStrategy implements the D3b interface.
// Original Java class: flb
type StyledOnmouseoverStrategy struct {
	payloadPrefix       string // Corresponds to 'b' (var1 - prefix) in Java
	randomContent       string // Corresponds to 'e' (var2 - random_string_5 literal or content)
	attributeSpacing    string // Corresponds to 'd' (var3 - attribute_spacing)
	quoteCharacter      string // Corresponds to 'a' (var4 - quote_char)
	isReflectionPresent bool   // Corresponds to 'c' (var5 - reflection_is_present)
}

// NewStyledOnmouseoverStrategy creates a new instance of Flb.
// Original Java constructor: public flb(String var1, String var2, String var3, String var4, boolean var5)
func NewStyledOnmouseoverStrategy(
	prefix, randomContent, attributeSpacing, quoteChar string,
	reflectionIsPresent bool,
) *StyledOnmouseoverStrategy {
	return &StyledOnmouseoverStrategy{
		payloadPrefix:       prefix,
		randomContent:       randomContent,
		attributeSpacing:    attributeSpacing,
		quoteCharacter:      quoteChar,
		isReflectionPresent: reflectionIsPresent,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the d3b interface for class Flb.
// Original Java method: public bgf a(hgm var1, hnx var2, byte var3, byte var4, eqx var5, byte[] var6)
func (receiver *StyledOnmouseoverStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// String var7 = this.b // prefix
	//    + "#{random_string_5}" // Java code uses this.e here, which is randStr5. The literal string is part of the pattern.
	//    + this.e
	//    + this.d
	//    + "onmouseover=" ...
	// Based on Java var7 construction: this.e is used for the first random string placeholder as well as its own content.
	// For strict porting, if this.e (ValEStr) is intended to be "#{random_string_5}", it should be passed as such to NewFlb.
	// If the Java code meant `this.b + SOME_RANDOM_STRING_PLACEHOLDER + this.e + this.d...` then ValEStr is the second part.
	// Given the Java code `this.b + "#{random_string_5}" + this.e ...` this looks like an error in the original provided snippet analysis for flb,
	// because the string literal "#{random_string_5}" seems to be missing in the Java code shown in the XML for flb.java.
	// The provided java code is: `this.b + this.e + this.d + ...` (if `this.e` is `var2` which is `#{random_string_5}` from constructor analysis)
	// The repomix for flb.java: `String var7 = this.b + "#{random_string_5}" + this.e + this.d + ...` (This matches my original plan for f00's flb call)
	// I will stick to the repomix version as it seems more likely for these patterns.
	// So this.e from constructor IS the var2 (randStr5 content), NOT the literal "#{random_string_5}".

	formattedPayload := receiver.payloadPrefix + // this.b (prefix)
		"#{random_string_5}" + // literal placeholder
		receiver.randomContent + // this.e (randStr5 content from constructor)
		receiver.attributeSpacing + // this.d (attribute_spacing)
		"onmouseover=" +
		receiver.quoteCharacter + // this.a (quote_char)
		"#{poc}" +
		receiver.quoteCharacter + // this.a (quote_char)
		receiver.attributeSpacing + // this.d (attribute_spacing)
		"style=" +
		receiver.quoteCharacter + // this.a (quote_char)
		"position:absolute;width:100%;height:100%;top:0;left:0;" +
		receiver.quoteCharacter + // this.a (quote_char)
		receiver.attributeSpacing + // this.d (attribute_spacing)
		"#{random_string_5b}"

	// var2.a(new bg8(var4, "onmouseover")).a(this.c)
	finalProfile := profile.WithAdditionalMatchCriterion(NewAttributeValueEventMatcher(contextType, "onmouseover")).
		WithAdvancedMode(receiver.isReflectionPresent)

	// return var1.a(20).a((byte)2, var7, hnxResult);
	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
