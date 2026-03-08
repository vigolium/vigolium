package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// HTMLEncodedJavaScriptSchemeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: dtt
type HTMLEncodedJavaScriptSchemeStrategy struct{}

// NewHTMLEncodedJavaScriptSchemeStrategy creates a new instance of Dtt.
// Original Java class does not have an explicit constructor shown, implies default constructor.
func NewHTMLEncodedJavaScriptSchemeStrategy() *HTMLEncodedJavaScriptSchemeStrategy {
	return &HTMLEncodedJavaScriptSchemeStrategy{}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *HTMLEncodedJavaScriptSchemeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return var1.a(260).a((byte)11, "&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;#{poc}//#{random_string_8}", var2.f());

	formattedPayload := "&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;#{poc}//#{random_string_8}"

	// var1.a(260)
	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(260)

	// var2.f()
	finalProfile := profile.WithDetectorValidation()

	// .a((byte)11, payload, processedHnx)
	return adjustedProbeBuilder.BuildFinding(byte(11), formattedPayload, finalProfile)
}
