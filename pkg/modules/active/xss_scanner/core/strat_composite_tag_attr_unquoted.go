package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// TagAttributeUnquotedCompositeStrategy implements the ContextualXSSTechnique interface.
type TagAttributeUnquotedCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewTagAttributeUnquotedCompositeStrategy creates a new instance.
func NewTagAttributeUnquotedCompositeStrategy() *TagAttributeUnquotedCompositeStrategy {
	greaterThanBreakoutStrategy := NewGenericBreakoutCompositeStrategy(">", false)
	simpleAttributeStrategy := NewSimpleAttributeInjectionStrategy()

	doubleQuotedAttrStrategy := NewQuotedAttributeContextStrategy(
		charDoubleQuote,
	)
	singleQuotedAttrStrategy := NewQuotedAttributeContextStrategy(
		charSingleQuote,
	)
	backtickQuotedAttrStrategy := NewQuotedAttributeContextStrategy(charBacktick)

	quotedAttrIteratorStrategy := NewFirstSuccessMetaStrategy(
		doubleQuotedAttrStrategy,
		singleQuotedAttrStrategy,
		backtickQuotedAttrStrategy,
	)
	conditionalMetaStrategy := NewConditionalExecutionMetaStrategy(
		quotedAttrIteratorStrategy,
	)

	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		greaterThanBreakoutStrategy,
		simpleAttributeStrategy,
		conditionalMetaStrategy,
	)

	return &TagAttributeUnquotedCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *TagAttributeUnquotedCompositeStrategy) GeneratePayload(
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
