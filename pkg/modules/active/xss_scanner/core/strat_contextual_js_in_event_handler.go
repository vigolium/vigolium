package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptInEventHandlerStrategy implements the ContextualXSSTechnique interface.
type JavaScriptInEventHandlerStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewJavaScriptInEventHandlerStrategy creates a new instance.
func NewJavaScriptInEventHandlerStrategy(
	contentType *ContentTypeProfile,
	quoteChar string,
) *JavaScriptInEventHandlerStrategy {
	smartQuoteHandlerStrategy := NewJavaScriptSmartQuoteHandlerStrategy(contentType)
	attributeBreakoutStrategy := NewQuotedAttributeBreakoutStrategy(quoteChar)
	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		smartQuoteHandlerStrategy,
		attributeBreakoutStrategy,
	)

	return &JavaScriptInEventHandlerStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *JavaScriptInEventHandlerStrategy) GeneratePayload(
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
