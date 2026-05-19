package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JSCommentTerminatorVariantStrategy implements the ContextualXSSTechnique interface.
type JSCommentTerminatorVariantStrategy struct {
	variantGeneratingStrategy ContextualAttackPayloadGenerator
}

func createJSCommentTerminatorPayload(
	terminator string,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := "#{random_string_5}" + terminator + "#{random_string_5b}"
	return probeBuilder.WithoutSecondaryCanary().BuildFinding(byte(4), formattedPayload, profile)
}

// NewJSCommentTerminatorVariantStrategy creates a new instance.
func NewJSCommentTerminatorVariantStrategy(
	terminatorBase string,
	unusedString string,
	useHTMLEntityVariants bool,
) *JSCommentTerminatorVariantStrategy {
	receiver := &JSCommentTerminatorVariantStrategy{}

	strategyFactory := &jsCommentTerminatorStrategyFactoryAdapter{
		parentStrategy:          receiver,
		capturedTerminatorBase:  terminatorBase,
		capturedUseVariantsFlag: useHTMLEntityVariants,
	}

	receiver.variantGeneratingStrategy = NewHTMLEntityVariantCompositeStrategy(
		terminatorBase,
		useHTMLEntityVariants,
		strategyFactory,
	)

	return receiver
}

// createStrategyForTerminator returns a ContextualAttackPayloadGenerator for the given terminator.
func (strategy *JSCommentTerminatorVariantStrategy) createStrategyForTerminator(
	terminator string,
) ContextualAttackPayloadGenerator {
	return &jsCommentTerminatorLambdaWrapper{capturedTerminator: terminator}
}

func (receiver *JSCommentTerminatorVariantStrategy) GeneratePayload(
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

// jsCommentTerminatorLambdaWrapper implements ContextualAttackPayloadGenerator for a specific terminator.
type jsCommentTerminatorLambdaWrapper struct {
	capturedTerminator string
}

func (w *jsCommentTerminatorLambdaWrapper) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return createJSCommentTerminatorPayload(
		w.capturedTerminator,
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}

// jsCommentTerminatorStrategyFactoryAdapter implements StrategyGeneratorFromString for JS comment terminator variants.
type jsCommentTerminatorStrategyFactoryAdapter struct {
	parentStrategy          *JSCommentTerminatorVariantStrategy
	capturedTerminatorBase  string
	capturedUseVariantsFlag bool
}

func (adapter *jsCommentTerminatorStrategyFactoryAdapter) IsStrategyFactoryFromString() {}

// CreateStrategy implements the StrategyGeneratorFromString interface.
func (adapter *jsCommentTerminatorStrategyFactoryAdapter) CreateStrategy(
	terminatorVariant string,
) ContextualAttackPayloadGenerator {
	terminatorPayloadStrategy := adapter.parentStrategy.createStrategyForTerminator(
		terminatorVariant,
	)

	numericStringVariantStrategy := NewJSNumericStringVariantCompositeStrategy(
		adapter.capturedTerminatorBase,
		adapter.capturedTerminatorBase,
		adapter.capturedUseVariantsFlag,
	)

	return NewSequentialMetaStrategy(
		terminatorPayloadStrategy,
		numericStringVariantStrategy,
	)
}
