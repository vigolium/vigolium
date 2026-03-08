package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// AccessKeyOnclickStrategy implements the ContextualXSSTechnique interface.
// Original Java class: aic
type AccessKeyOnclickStrategy struct {
	prefix                   string // Corresponds to 'c' in Java
	randomComponent          string // Corresponds to 'd' in Java
	attributeSpacingAndQuote string // Corresponds to 'e' in Java
	accessKeyChar            string // Corresponds to 'a' in Java
	useAdvancedMode          bool   // Corresponds to 'b' in Java
}

// NewAccessKeyOnclickStrategy creates a new instance of Aic.
// Original Java constructor: public aic(String var1, String var2, String var3, String var4, boolean var5)
func NewAccessKeyOnclickStrategy(
	prefix, randomComp, attrSpaceQuote, accessKeyChar string,
	advancedMode bool,
) *AccessKeyOnclickStrategy {
	return &AccessKeyOnclickStrategy{
		prefix:                   prefix,
		randomComponent:          randomComp,
		attributeSpacingAndQuote: attrSpaceQuote,
		accessKeyChar:            accessKeyChar,
		useAdvancedMode:          advancedMode,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *AccessKeyOnclickStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic for var7:
	// String var7 = this.c
	//    + "#{random_string_5}"
	//    + this.d
	//    + this.e
	//    + "accesskey="
	//    + this.a
	//    + "x"
	//    + this.a
	//    + this.e
	//    + "onclick="
	//    + this.a
	//    + "#{poc}"
	//    + this.a
	//    + "//#{random_string_5b}";
	formattedPayload := receiver.prefix +
		"#{random_string_5}" +
		receiver.randomComponent +
		receiver.attributeSpacingAndQuote +
		"accesskey=" +
		receiver.accessKeyChar +
		"x" +
		receiver.accessKeyChar +
		receiver.attributeSpacingAndQuote +
		"onclick=" +
		receiver.accessKeyChar +
		"#{poc}" +
		receiver.accessKeyChar +
		"//#{random_string_5b}"

	// Ported logic:
	// var2.a(new dp_(var4)).a(this.b)
	// Hnx methods now return Hnx for chaining.
	finalProfile := profile.WithAdditionalMatchCriterion(NewContextSpecificReflectionMatcher(contextType)).
		WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithAdditionalScanFlags(65540).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
