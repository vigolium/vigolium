package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptOperatorInjectionStrategy implements the ContextualXSSTechnique interface.
// Original Java class: ckn
type JavaScriptOperatorInjectionStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewJavaScriptOperatorInjectionStrategy creates a new instance of Ckn.
// Original Java constructor: public ckn(g41... var1)
func NewJavaScriptOperatorInjectionStrategy(
	operatorStrategyFactories ...StrategyGeneratorFromOperator,
) *JavaScriptOperatorInjectionStrategy {
	jsOperators := []string{
		"-", "+", "*", "^", "&", "|", "%", "/", "==",
	}

	factoryCount := len(operatorStrategyFactories)
	operatorCount := len(jsOperators)

	generatedStrategies := make([]ContextualAttackPayloadGenerator, operatorCount*factoryCount)

	strategyIndex := 0

outerLoop:
	for factoryIdx := 0; factoryIdx < factoryCount; factoryIdx++ {
		for operatorIdx := 0; operatorIdx < operatorCount; operatorIdx++ {
			if strategyIndex >= len(generatedStrategies) {
				break outerLoop
			}
			currentOperator := jsOperators[operatorIdx]
			currentFactory := operatorStrategyFactories[factoryIdx]
			generatedStrategies[strategyIndex] = currentFactory.CreateStrategy(currentOperator)
			strategyIndex++

		}
	}

	return &JavaScriptOperatorInjectionStrategy{
		combinedStrategy: NewFirstSuccessMetaStrategy(generatedStrategies[:strategyIndex]...),
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Ckn.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JavaScriptOperatorInjectionStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// return this.a.a(var1, var2, var3, var4, var5, var6);
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
