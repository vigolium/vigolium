package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptSchemeCompositeStrategy implements the ContextualXSSTechnique interface.
type JavaScriptSchemeCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewJavaScriptSchemeCompositeStrategy creates a new instance.
func NewJavaScriptSchemeCompositeStrategy(
	randomProvider *utils.RandomGenerator,
	contentType *ContentTypeProfile,
) *JavaScriptSchemeCompositeStrategy {

	encodedSchemeStrategy := NewEncodedJavaScriptSchemeCompositeStrategy(
		randomProvider,
	)
	scriptAttributeStrategy := NewScriptSchemeInAttributeStrategy(
		contentType,
	)
	vbscriptAttributeStrategy := NewVBScriptAttributeStrategy()

	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		encodedSchemeStrategy,
		scriptAttributeStrategy,
		vbscriptAttributeStrategy,
	)

	return &JavaScriptSchemeCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *JavaScriptSchemeCompositeStrategy) GeneratePayload(
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
