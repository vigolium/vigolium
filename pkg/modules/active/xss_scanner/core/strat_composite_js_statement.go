package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptStatementCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: hfu
type JavaScriptStatementCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewJavaScriptStatementCompositeStrategy creates a new instance of Hfu.
// The field 'a' in Java is initialized directly: new e_w(new es9(), new g4h(";", ";", false))
func NewJavaScriptStatementCompositeStrategy() *JavaScriptStatementCompositeStrategy {
	simpleCallStrategy := NewJavaScriptSimpleCallStrategy() // Ported
	// NewG4h needs to be available from g4h.go or a correct stub
	semicolonVariantStrategy := NewJSNumericStringVariantCompositeStrategy(";", ";", false)
	pairedExecutor := NewPairedStrategyExecutor(
		simpleCallStrategy,
		semicolonVariantStrategy,
	) // Ported

	return &JavaScriptStatementCompositeStrategy{
		combinedStrategy: pairedExecutor,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Hfu.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JavaScriptStatementCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return this.a.a(var1, var2, var3, var4, var5, var6);
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
