package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// HTMLEncodedJavaScriptSchemeStrategy implements the ContextualXSSTechnique interface.
type HTMLEncodedJavaScriptSchemeStrategy struct{}

// NewHTMLEncodedJavaScriptSchemeStrategy creates a new instance.
func NewHTMLEncodedJavaScriptSchemeStrategy() *HTMLEncodedJavaScriptSchemeStrategy {
	return &HTMLEncodedJavaScriptSchemeStrategy{}
}

func (receiver *HTMLEncodedJavaScriptSchemeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := "&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;#{poc}//#{random_string_8}"

	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(260)

	finalProfile := profile.WithDetectorValidation()

	return adjustedProbeBuilder.BuildFinding(byte(11), formattedPayload, finalProfile)
}
