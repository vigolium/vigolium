package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// OnfocusEventHandlerStrategy implements the ContextualXSSTechnique interface.
type OnfocusEventHandlerStrategy struct {
	prefix                    string
	randomComponent1          string
	attributeSpacingAndTagEnd string
	quoteChar                 string
	useAdvancedMode           bool
}

// NewOnfocusEventHandlerStrategy creates a new instance.
func NewOnfocusEventHandlerStrategy(
	prefix, rndComp1, attrSpacingTagEnd, quote string,
	advancedMode bool,
) *OnfocusEventHandlerStrategy {
	return &OnfocusEventHandlerStrategy{
		prefix:                    prefix,
		randomComponent1:          rndComp1,
		attributeSpacingAndTagEnd: attrSpacingTagEnd,
		quoteChar:                 quote,
		useAdvancedMode:           advancedMode,
	}
}

func (receiver *OnfocusEventHandlerStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := receiver.prefix + "#{random_string_5}" + receiver.randomComponent1 + receiver.attributeSpacingAndTagEnd +
		"onfocus=" + receiver.quoteChar + "#{poc}" + receiver.quoteChar + receiver.attributeSpacingAndTagEnd +
		"#{random_string_5b}"

	finalProfile := profile.WithAdditionalMatchCriterion(NewAttributeValueEventMatcher(contextType, "onfocus")).
		WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
