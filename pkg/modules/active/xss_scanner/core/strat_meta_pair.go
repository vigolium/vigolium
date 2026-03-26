package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// PairedStrategyExecutor implements the ContextualXSSTechnique interface.
type PairedStrategyExecutor struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewPairedStrategyExecutor creates a new PairedStrategyExecutor instance.
func NewPairedStrategyExecutor(
	strategyOne ContextualAttackPayloadGenerator,
	strategyTwo ContextualAttackPayloadGenerator,
) *PairedStrategyExecutor {
	sequentialExecutor := NewSequentialMetaStrategy(strategyOne, strategyTwo)

	return &PairedStrategyExecutor{
		combinedStrategy: sequentialExecutor,
	}
}

func (executor *PairedStrategyExecutor) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return executor.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
