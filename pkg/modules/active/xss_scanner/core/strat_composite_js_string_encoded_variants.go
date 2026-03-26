package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// EncodedJSStringVariantStrategy implements the ContextualXSSTechnique interface.
type EncodedJSStringVariantStrategy struct {
	variantGeneratingStrategy ContextualAttackPayloadGenerator
}

func createEncodedJSStringPayload(
	params JavaScriptPayloadParams,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	mainFormattedPayload := "#{random_string_5}" + params.primaryComponent + "#{random_string_5b}"
	profilePayloadComponent := "#{random_string_5}" + params.encodedComponent + "#{random_string_5b}"

	finalProfile := profile.WithVariantCanaryComponent(profilePayloadComponent)
	return probeBuilder.WithoutSecondaryCanary().
		WithAdditionalScanFlags(params.flag).
		BuildFinding(byte(4), mainFormattedPayload, finalProfile)
}

// encodedJSStringLambdaWrapper implements ContextualAttackPayloadGenerator for encoded JS string payloads.
type encodedJSStringLambdaWrapper struct {
	capturedParams JavaScriptPayloadParams
}

func (w *encodedJSStringLambdaWrapper) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return createEncodedJSStringPayload(
		w.capturedParams,
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}

func (receiver *EncodedJSStringVariantStrategy) createPayloadStrategy(
	amVal JavaScriptPayloadParams,
) ContextualAttackPayloadGenerator {
	return &encodedJSStringLambdaWrapper{capturedParams: amVal}
}

// encodedJSStringStrategyFactoryAdapter implements StrategyGeneratorFromString for encoded JS string variants.
type encodedJSStringStrategyFactoryAdapter struct {
	parentStrategy                    *EncodedJSStringVariantStrategy
	capturedBaseParams                JavaScriptPayloadParams
	capturedUseHTMLEntityVariantsFlag bool
}

func (adapter *encodedJSStringStrategyFactoryAdapter) IsStrategyFactoryFromString() {}

func (adapter *encodedJSStringStrategyFactoryAdapter) CreateStrategy(
	payloadComponent string,
) ContextualAttackPayloadGenerator {
	modifiedParams := JavaScriptPayloadParams{
		primaryComponent: payloadComponent,
		encodedComponent: adapter.capturedBaseParams.encodedComponent,
		flag:             adapter.capturedBaseParams.flag,
	}
	return adapter.parentStrategy.createPayloadStrategy(modifiedParams)
}

// NewEncodedJSStringVariantStrategy creates a new instance.
func NewEncodedJSStringVariantStrategy(
	baseParams JavaScriptPayloadParams,
	useHTMLEntityVariants bool,
) *EncodedJSStringVariantStrategy {
	receiver := &EncodedJSStringVariantStrategy{}

	strategyFactory := &encodedJSStringStrategyFactoryAdapter{
		parentStrategy:                    receiver,
		capturedBaseParams:                baseParams,
		capturedUseHTMLEntityVariantsFlag: useHTMLEntityVariants,
	}

	receiver.variantGeneratingStrategy = NewHTMLEntityVariantCompositeStrategy(
		baseParams.primaryComponent,
		useHTMLEntityVariants,
		strategyFactory,
	)

	return receiver
}

func (receiver *EncodedJSStringVariantStrategy) GeneratePayload(
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
