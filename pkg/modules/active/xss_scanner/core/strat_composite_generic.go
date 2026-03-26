package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// GenericXSSCompositeStrategy implements the ContextualXSSTechnique interface.
type GenericXSSCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewGenericXSSCompositeStrategy creates a new instance.
func NewGenericXSSCompositeStrategy(
	prefix string,
	useAdvancedMode bool,
) *GenericXSSCompositeStrategy {


	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		NewSimpleAnchorTagStrategy(prefix),
		NewPairedStrategyExecutor(
			NewTagBreakoutStrategy(useAdvancedMode, prefix),
			NewFirstSuccessMetaStrategy(
				NewAngleBracketInvalidTagStrategy(useAdvancedMode, prefix),
				NewInvalidDoubleAngleTagStrategy(useAdvancedMode, prefix),
				NewNullByteInTagStrategy(useAdvancedMode, prefix),
				NewServerSideTagSyntaxStrategy(useAdvancedMode, prefix),
			),
		),
	)

	return &GenericXSSCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *GenericXSSCompositeStrategy) GeneratePayload(
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
