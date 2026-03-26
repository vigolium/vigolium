package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// BasicOnmouseoverStrategy implements the ContextualXSSTechnique interface.
type BasicOnmouseoverStrategy struct {
	prefix                    string
	randomComponent           string
	attributeSpacingAndTagEnd string
	quoteChar                 string
	useAdvancedMode           bool
}

// NewBasicOnmouseoverStrategy creates a new instance.
func NewBasicOnmouseoverStrategy(
	prefix, randomComp, attrSpaceTagEnd, quote string,
	advancedMode bool,
) *BasicOnmouseoverStrategy {
	return &BasicOnmouseoverStrategy{
		prefix:                    prefix,
		randomComponent:           randomComp,
		attributeSpacingAndTagEnd: attrSpaceTagEnd,
		quoteChar:                 quote,
		useAdvancedMode:           advancedMode,
	}
}

func (receiver *BasicOnmouseoverStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := receiver.prefix + "#{random_string_5}" + receiver.randomComponent + receiver.attributeSpacingAndTagEnd +
		"onmouseover=" + receiver.quoteChar + "#{poc}" + receiver.quoteChar + receiver.attributeSpacingAndTagEnd +
		"#{random_string_5b}"

	finalProfile := profile.WithAdditionalMatchCriterion(NewAttributeValueEventMatcher(contextType, "onmouseover")).
		WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
