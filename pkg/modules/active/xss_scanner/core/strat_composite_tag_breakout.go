package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SpecificTagBreakoutCompositeStrategy implements the ContextualXSSTechnique interface.
type SpecificTagBreakoutCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewSpecificTagBreakoutCompositeStrategy creates a new instance.
func NewSpecificTagBreakoutCompositeStrategy(
	tagName string,
	contextCode byte,
) *SpecificTagBreakoutCompositeStrategy {

	simpleClosingTagStrategy := NewClosingTagStrategy(tagName, contextCode)
	closingTagPayload1 := "</" + tagName + ">"
	genericBreakoutStrategy1 := NewGenericBreakoutCompositeStrategy(closingTagPayload1, false)
	sequence1 := NewSequentialMetaStrategy(simpleClosingTagStrategy, genericBreakoutStrategy1)

	processedClosingTagStrategy := NewProcessedClosingTagStrategy(tagName, contextCode)
	processedTagName := mangleTagNameForClosing(tagName)
	closingTagPayload2 := "</" + processedTagName + " >"
	genericBreakoutStrategy2 := NewGenericBreakoutCompositeStrategy(closingTagPayload2, false)
	sequence2 := NewSequentialMetaStrategy(processedClosingTagStrategy, genericBreakoutStrategy2)

	finalCombinedStrategy := NewFirstSuccessMetaStrategy(sequence1, sequence2)

	return &SpecificTagBreakoutCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *SpecificTagBreakoutCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
