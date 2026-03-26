package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// HTMLCommentBreakoutCompositeStrategy implements the ContextualXSSTechnique interface.
type HTMLCommentBreakoutCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewHTMLCommentBreakoutCompositeStrategy creates a new instance.
func NewHTMLCommentBreakoutCompositeStrategy() *HTMLCommentBreakoutCompositeStrategy {
	commentCloserStrategy := NewHTMLCommentCloserStrategy()
	genericBreakoutStrategy := NewGenericBreakoutCompositeStrategy("-->", false)
	finalCombinedStrategy := NewSequentialMetaStrategy(commentCloserStrategy, genericBreakoutStrategy)
	return &HTMLCommentBreakoutCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *HTMLCommentBreakoutCompositeStrategy) GeneratePayload(
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
