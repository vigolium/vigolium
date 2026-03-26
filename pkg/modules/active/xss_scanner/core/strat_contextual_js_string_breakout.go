package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptStringBreakoutStrategy implements the ContextualXSSTechnique interface.
type JavaScriptStringBreakoutStrategy struct {
	combinedStrategy         ContextualAttackPayloadGenerator
	enableHtmlEntityDecoding bool
}
type JSStringComponentBuilder interface {
	BuildComponents(baseString string, params JavaScriptPayloadParams) JSStringPayloadComponents
}
type JSStringPayloadComponents struct {
	payloadWithBaseSuffix        string
	encodedPayloadWithBaseSuffix string
	baseSuffix                   string
	encodedBaseSuffix            string
}

// --- Static Lambdas as Package-Level Functions ---

func buildJSStringComponentsDefault(
	baseString string,
	params JavaScriptPayloadParams,
) JSStringPayloadComponents {
	return JSStringPayloadComponents{
		payloadWithBaseSuffix:        params.primaryComponent + baseString,
		encodedPayloadWithBaseSuffix: params.encodedComponent + baseString,
		baseSuffix:                   baseString + params.primaryComponent,
		encodedBaseSuffix:            baseString + params.encodedComponent,
	}
}

func buildJSStringComponentsWithCommentSuffix(
	baseString string,
	params JavaScriptPayloadParams,
) JSStringPayloadComponents {
	return JSStringPayloadComponents{
		payloadWithBaseSuffix:        params.primaryComponent + baseString,
		encodedPayloadWithBaseSuffix: params.encodedComponent + baseString,
		baseSuffix:                   "//",
		encodedBaseSuffix:            "//",
	}
}

func createJSStringBreakoutStrategyFromOperator(
	builder JSStringComponentBuilder,
	params JavaScriptPayloadParams,
	operator string,
) ContextualAttackPayloadGenerator {
	payloadComponents := builder.BuildComponents(operator, params)
	return NewJSStringFromComponentsStrategy(
		payloadComponents,
	)
}

// --- Adapters for Functional Interfaces ---

// jsStringComponentBuilderAdapter implements JSStringComponentBuilder using a function pointer.
type jsStringComponentBuilderAdapter struct {
	builderFunc func(baseStr string, params JavaScriptPayloadParams) JSStringPayloadComponents
}

func (e *jsStringComponentBuilderAdapter) BuildComponents(
	baseString string,
	params JavaScriptPayloadParams,
) JSStringPayloadComponents {
	return e.builderFunc(baseString, params)
}

// jsStringBreakoutStrategyFactoryAdapter implements StrategyGeneratorFromOperator, capturing a component builder and payload params.
type jsStringBreakoutStrategyFactoryAdapter struct {
	componentBuilder JSStringComponentBuilder
	payloadParams    JavaScriptPayloadParams
}

func (w *jsStringBreakoutStrategyFactoryAdapter) CreateStrategy(
	operator string,
) ContextualAttackPayloadGenerator {
	return createJSStringBreakoutStrategyFromOperator(w.componentBuilder, w.payloadParams, operator)
}

// --- Private Helper Method ---

func (receiver *JavaScriptStringBreakoutStrategy) buildCoreBreakoutLogic(
	componentBuilder JSStringComponentBuilder,
	params JavaScriptPayloadParams,
	useVariants bool,
) ContextualAttackPayloadGenerator {

	encodedVariantStrategy := NewEncodedJSStringVariantStrategy(params, useVariants)
	semicolonInjectionStrategy := NewJavaScriptSemicolonInjectionStrategy(params, useVariants)

	strategyFactoryAdapter := &jsStringBreakoutStrategyFactoryAdapter{
		componentBuilder: componentBuilder,
		payloadParams:    params,
	}
	operatorInjectionStrategy := NewJavaScriptOperatorInjectionStrategy(
		strategyFactoryAdapter,
	)

	semicolonVariantStrategy := NewJSStringSemicolonVariantStrategy(params, useVariants)
	innerIteratorStrategy := NewFirstSuccessMetaStrategy(
		semicolonInjectionStrategy,
		operatorInjectionStrategy,
		semicolonVariantStrategy,
	)

	return NewSequentialMetaStrategy(encodedVariantStrategy, innerIteratorStrategy)
}

// --- Constructor ---

// NewJavaScriptStringBreakoutStrategy creates a new instance.
func NewJavaScriptStringBreakoutStrategy(
	quoteChar string,
	contentType *ContentTypeProfile,
	enableAdvancedMode bool,
) *JavaScriptStringBreakoutStrategy {
	receiver := &JavaScriptStringBreakoutStrategy{enableHtmlEntityDecoding: enableAdvancedMode}

	paramsForQuote := JavaScriptPayloadParams{primaryComponent: quoteChar, encodedComponent: quoteChar, flag: 0}

	paramsForEscapedQuote := JavaScriptPayloadParams{
		primaryComponent: "\\" + quoteChar,
		encodedComponent: "\\\\" + quoteChar,
		flag:             64,
	}

	defaultComponentBuilder := &jsStringComponentBuilderAdapter{
		builderFunc: buildJSStringComponentsDefault,
	}

	commentSuffixComponentBuilder := &jsStringComponentBuilderAdapter{
		builderFunc: buildJSStringComponentsWithCommentSuffix,
	}

	scriptTagCheckStrategy := NewConditionalScriptTagCheckMetaStrategy(
		contentType,
		enableAdvancedMode,
	)
	breakoutStrategyWithQuote := receiver.buildCoreBreakoutLogic(
		defaultComponentBuilder,
		paramsForQuote,
		enableAdvancedMode,
	)
	breakoutStrategyWithEscapedQuote := receiver.buildCoreBreakoutLogic(
		commentSuffixComponentBuilder,
		paramsForEscapedQuote,
		enableAdvancedMode,
	)

	receiver.combinedStrategy = NewFirstSuccessMetaStrategy(
		breakoutStrategyWithQuote,
		breakoutStrategyWithEscapedQuote,
		scriptTagCheckStrategy,
	)
	return receiver
}

// --- ContextualAttackPayloadGenerator interface ---

func (receiver *JavaScriptStringBreakoutStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	finalProfile := profile
	if receiver.enableHtmlEntityDecoding {
		finalProfile = profile.WithHtmlEntityDecoding()
	}

	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		finalProfile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
