package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeSpecificPayloadCompositeStrategy implements the ContextualXSSTechnique interface.
type SchemeSpecificPayloadCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewSchemeSpecificPayloadCompositeStrategy creates a new instance.
func NewSchemeSpecificPayloadCompositeStrategy(
	scheme SchemeDefinition,
) *SchemeSpecificPayloadCompositeStrategy {

	schemeRandomStrategy := NewSchemeWithRandomStringStrategy(scheme, "")

	schemePocRandomStrategy := NewSchemeWithPocAndRandomStringStrategy(scheme, "")

	finalCombinedStrategy := NewSequentialMetaStrategy(schemeRandomStrategy, schemePocRandomStrategy)

	return &SchemeSpecificPayloadCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *SchemeSpecificPayloadCompositeStrategy) GeneratePayload(
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
