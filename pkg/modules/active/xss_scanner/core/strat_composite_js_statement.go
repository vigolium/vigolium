package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptStatementCompositeStrategy implements the ContextualXSSTechnique interface.
type JavaScriptStatementCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewJavaScriptStatementCompositeStrategy creates a new instance.
func NewJavaScriptStatementCompositeStrategy() *JavaScriptStatementCompositeStrategy {
	simpleCallStrategy := NewJavaScriptSimpleCallStrategy()
	semicolonVariantStrategy := NewJSNumericStringVariantCompositeStrategy(";", ";", false)
	pairedExecutor := NewPairedStrategyExecutor(
		simpleCallStrategy,
		semicolonVariantStrategy,
	)

	return &JavaScriptStatementCompositeStrategy{
		combinedStrategy: pairedExecutor,
	}
}

func (receiver *JavaScriptStatementCompositeStrategy) GeneratePayload(
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
