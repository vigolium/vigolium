package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// PairedStrategyExecutor implements the ContextualXSSTechnique interface.
// Original Java class: e_w (renamed to PairedStrategyExecutor for Go convention)
type PairedStrategyExecutor struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewPairedStrategyExecutor creates a new instance of EW.
// Original Java constructor: public e_w(ContextualXSSTechnique var1, ContextualXSSTechnique var2)
func NewPairedStrategyExecutor(
	strategyOne ContextualAttackPayloadGenerator,
	strategyTwo ContextualAttackPayloadGenerator,
) *PairedStrategyExecutor {
	// Original Java logic: this.a = new c0b(var1, var2);
	// NewC0b is the constructor from the ported c0b.go which returns *C0b.
	// *C0b implements ContextualXSSTechnique.
	sequentialExecutor := NewSequentialMetaStrategy(strategyOne, strategyTwo)

	return &PairedStrategyExecutor{
		combinedStrategy: sequentialExecutor, // c0bInstance is a *C0b, which fulfills ContextualXSSTechnique interface
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class EW.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (executor *PairedStrategyExecutor) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return this.a.a(var1, var2, var3, var4, var5, var6);
	return executor.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
