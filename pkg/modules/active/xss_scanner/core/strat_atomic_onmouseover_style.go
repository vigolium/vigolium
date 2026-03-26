package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// StyledOnmouseoverStrategy implements the ContextualAttackPayloadGenerator interface.
type StyledOnmouseoverStrategy struct {
	payloadPrefix       string
	randomContent       string
	attributeSpacing    string
	quoteCharacter      string
	isReflectionPresent bool
}

// NewStyledOnmouseoverStrategy creates a new instance.
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

func (receiver *StyledOnmouseoverStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := receiver.payloadPrefix +
		"#{random_string_5}" +
		receiver.randomContent +
		receiver.attributeSpacing +
		"onmouseover=" +
		receiver.quoteCharacter +
		"#{poc}" +
		receiver.quoteCharacter +
		receiver.attributeSpacing +
		"style=" +
		receiver.quoteCharacter +
		"position:absolute;width:100%;height:100%;top:0;left:0;" +
		receiver.quoteCharacter +
		receiver.attributeSpacing +
		"#{random_string_5b}"

	finalProfile := profile.WithAdditionalMatchCriterion(NewAttributeValueEventMatcher(contextType, "onmouseover")).
		WithAdvancedMode(receiver.isReflectionPresent)

	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
