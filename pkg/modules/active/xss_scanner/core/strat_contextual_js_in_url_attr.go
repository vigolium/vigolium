package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptInURLAttributeStrategy implements the ContextualXSSTechnique interface.
type JavaScriptInURLAttributeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewJavaScriptInURLAttributeStrategy creates a new instance.
func NewJavaScriptInURLAttributeStrategy(
	randomProvider *utils.RandomGenerator,
	contentType *ContentTypeProfile,
	quoteChar string,
) *JavaScriptInURLAttributeStrategy {
	jsSchemeStrategy := NewJavaScriptSchemeCompositeStrategy(randomProvider, contentType)
	attributeBreakoutStrategy := NewQuotedAttributeBreakoutStrategy(quoteChar)
	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		jsSchemeStrategy,
		attributeBreakoutStrategy,
	)

	return &JavaScriptInURLAttributeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *JavaScriptInURLAttributeStrategy) GeneratePayload(
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
