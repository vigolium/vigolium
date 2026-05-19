package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptOperatorInjectionStrategy implements the ContextualXSSTechnique interface.
type JavaScriptOperatorInjectionStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewJavaScriptOperatorInjectionStrategy creates a new instance.
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

func (receiver *JavaScriptOperatorInjectionStrategy) GeneratePayload(
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
