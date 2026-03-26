package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JSInUnquotedURLAttributeCompositeStrategy implements the ContextualXSSTechnique interface.
type JSInUnquotedURLAttributeCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewJSInUnquotedURLAttributeCompositeStrategy creates a new instance.
func NewJSInUnquotedURLAttributeCompositeStrategy(
	randomProvider *utils.RandomGenerator,
	contentType *ContentTypeProfile,
) *JSInUnquotedURLAttributeCompositeStrategy {

	jsSchemeCompositeStrategy := NewJavaScriptSchemeCompositeStrategy(
		randomProvider,
		contentType,
	)
	tagAttributeUnquotedStrategy := NewTagAttributeUnquotedCompositeStrategy()
	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		jsSchemeCompositeStrategy,
		tagAttributeUnquotedStrategy,
	)
	return &JSInUnquotedURLAttributeCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *JSInUnquotedURLAttributeCompositeStrategy) GeneratePayload(
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
