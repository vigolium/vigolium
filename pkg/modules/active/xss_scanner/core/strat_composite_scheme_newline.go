package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeWithNewlineCompositeStrategy implements the ContextualXSSTechnique interface.
type SchemeWithNewlineCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewSchemeWithNewlineCompositeStrategy creates a new instance.
func NewSchemeWithNewlineCompositeStrategy(
	scheme SchemeDefinition,
) *SchemeWithNewlineCompositeStrategy {

	schemeRandomStrategy := NewSchemeWithRandomStringStrategy(
		scheme,
		"//\n",
	)

	schemePocRandomStrategy := NewSchemeWithPocAndRandomStringStrategy(
		scheme,
		"//\n",
	)

	htmlEncodedSchemeStrategy := NewHTMLEncodedJavaScriptSchemeStrategy()

	iteratorStrategy := NewFirstSuccessMetaStrategy(
		schemePocRandomStrategy,
		htmlEncodedSchemeStrategy,
	)

	finalCombinedStrategy := NewSequentialMetaStrategy(
		schemeRandomStrategy,
		iteratorStrategy,
	)

	return &SchemeWithNewlineCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *SchemeWithNewlineCompositeStrategy) GeneratePayload(
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
