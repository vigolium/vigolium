package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// OnfocusAutofocusStrategy implements the ContextualXSSTechnique interface.
type OnfocusAutofocusStrategy struct {
	prefix           string
	randomComponent1 string
	attributeSpacing string
	quoteChar        string
	useAdvancedMode  bool
}

// NewOnfocusAutofocusStrategy creates a new instance.
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

func (receiver *OnfocusAutofocusStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := receiver.prefix +
		"#{random_string_5}" +
		receiver.randomComponent1 +
		receiver.attributeSpacing +
		"onfocus=" +
		receiver.quoteChar +
		"#{poc}" +
		receiver.quoteChar +
		receiver.attributeSpacing +
		"autofocus=" +
		receiver.quoteChar +
		receiver.attributeSpacing +
		"#{random_string_5b}"

	finalProfile := profile.WithAdditionalMatchCriterion(NewAttributeValueEventMatcher(contextType, "onfocus")).
		WithAdvancedMode(receiver.useAdvancedMode)
	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
