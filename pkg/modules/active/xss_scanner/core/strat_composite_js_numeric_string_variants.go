package core

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// JSNumericStringVariantCompositeStrategy implements the ContextualXSSTechnique interface.
type JSNumericStringVariantCompositeStrategy struct {
	variantGeneratingStrategy ContextualAttackPayloadGenerator
}

func createJSNumericStringPayload(
	basePayload string,
	constructorArg string,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	byteVal4 ReflectionTacticType,
	byteVal5 ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	bytesVal7 *utils.HTTPTransaction,
) PotentialXSSFinding {
	mainFormattedPayload := fmt.Sprintf(
		"#{random_numeric_string_5}%s#{poc}//#{random_numeric_string_3}",
		basePayload,
	)
	profilePayloadComponent := fmt.Sprintf(
		"#{random_numeric_string_5}%s#{poc}//#{random_numeric_string_3}",
		constructorArg,
	)

	finalProfile := profile.WithVariantCanaryComponent(profilePayloadComponent)
	return probeBuilder.WithAdditionalScanFlags(4).
		BuildFinding(byte(3), mainFormattedPayload, finalProfile)
}

// jsNumericStringLambdaWrapper implements ContextualAttackPayloadGenerator for numeric string payloads.
type jsNumericStringLambdaWrapper struct {
	capturedBasePayload    string
	capturedConstructorArg string
}

func (w *jsNumericStringLambdaWrapper) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return createJSNumericStringPayload(
		w.capturedBasePayload,
		w.capturedConstructorArg,
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}

func (receiver *JSNumericStringVariantCompositeStrategy) createPayloadStrategy(
	constructorArg string,
	basePayload string,
) ContextualAttackPayloadGenerator {
	return &jsNumericStringLambdaWrapper{
		capturedBasePayload:    basePayload,
		capturedConstructorArg: constructorArg,
	}
}

// jsNumericStringStrategyFactoryAdapter implements StrategyGeneratorFromString for numeric string variants.
type jsNumericStringStrategyFactoryAdapter struct {
	parentStrategy         *JSNumericStringVariantCompositeStrategy
	capturedConstructorArg string
}

func (adapter *jsNumericStringStrategyFactoryAdapter) IsStrategyFactoryFromString() {}

func (adapter *jsNumericStringStrategyFactoryAdapter) CreateStrategy(
	basePayload string,
) ContextualAttackPayloadGenerator {
	return adapter.parentStrategy.createPayloadStrategy(adapter.capturedConstructorArg, basePayload)
}

// NewJSNumericStringVariantCompositeStrategy creates a new instance.
func NewJSNumericStringVariantCompositeStrategy(
	variantBase string,
	constructorArg string,
	useHTMLEntityVariants bool,
) *JSNumericStringVariantCompositeStrategy {
	receiver := &JSNumericStringVariantCompositeStrategy{}

	strategyFactory := &jsNumericStringStrategyFactoryAdapter{
		parentStrategy:         receiver,
		capturedConstructorArg: constructorArg,
	}

	receiver.variantGeneratingStrategy = NewHTMLEntityVariantCompositeStrategy(
		variantBase,
		useHTMLEntityVariants,
		strategyFactory,
	)
	return receiver
}

func (receiver *JSNumericStringVariantCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return receiver.variantGeneratingStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
