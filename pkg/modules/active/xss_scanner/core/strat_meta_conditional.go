package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ConditionalExecutionMetaStrategy implements the ContextualXSSTechnique interface.
type ConditionalExecutionMetaStrategy struct {
	delegateStrategy ContextualAttackPayloadGenerator
}

// NewConditionalExecutionMetaStrategy creates a new instance of ConditionalExecutionMetaStrategy.
func NewConditionalExecutionMetaStrategy(
	delegateStrategy ContextualAttackPayloadGenerator,
) *ConditionalExecutionMetaStrategy {
	return &ConditionalExecutionMetaStrategy{
		delegateStrategy: delegateStrategy,
	}
}

func (receiver *ConditionalExecutionMetaStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	if contextType == ReflectionContextHTMLAttributeValueUnquotedBreakout && tactic != 1 {
		return receiver.delegateStrategy.GeneratePayload(
			probeBuilder,
			profile,
			tactic,
			contextType,
			reflection,
			transaction,
		)
	}
	return nil
}
