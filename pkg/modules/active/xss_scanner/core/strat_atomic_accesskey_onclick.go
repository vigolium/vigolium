package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// AccessKeyOnclickStrategy implements the ContextualXSSTechnique interface.
type AccessKeyOnclickStrategy struct {
	prefix                   string
	randomComponent          string
	attributeSpacingAndQuote string
	accessKeyChar            string
	useAdvancedMode          bool
}

// NewAccessKeyOnclickStrategy creates a new instance.
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

func (receiver *AccessKeyOnclickStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
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

	finalProfile := profile.WithAdditionalMatchCriterion(NewContextSpecificReflectionMatcher(contextType)).
		WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithAdditionalScanFlags(65540).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
