package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptStringBreakoutStrategy implements the ContextualXSSTechnique interface.
// Original Java class: ch8
type JavaScriptStringBreakoutStrategy struct {
	combinedStrategy         ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
	enableHtmlEntityDecoding bool                             // Corresponds to 'private final boolean b;'
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

// --- Static Lambdas Ported to Package-Level Functions ---

// buildJSStringComponentsDefault corresponds to Java: private static idh lambda$new$0(String var0, am_ var1)
func buildJSStringComponentsDefault(
	baseString string,
	params JavaScriptPayloadParams,
) JSStringPayloadComponents {
	// return new idh(var1.c + var0, var1.a + var0, var0 + var1.c, var0 + var1.a);
	return JSStringPayloadComponents{
		payloadWithBaseSuffix:        params.primaryComponent + baseString,
		encodedPayloadWithBaseSuffix: params.encodedComponent + baseString,
		baseSuffix:                   baseString + params.primaryComponent,
		encodedBaseSuffix:            baseString + params.encodedComponent,
		// C: var1.C + var0, // Payload part for var1.c
		// A: var1.A + var0, // Encoded payload part for var1.a
		// B: var0 + var1.C, // Suffix part
		// D: var0 + var1.A, // Encoded suffix part
	}
}

// buildJSStringComponentsWithCommentSuffix corresponds to Java: private static idh lambda$new$1(String var0, am_ var1)
func buildJSStringComponentsWithCommentSuffix(
	baseString string,
	params JavaScriptPayloadParams,
) JSStringPayloadComponents {
	// return new idh(var1.c + var0, var1.a + var0, "//", "//");
	return JSStringPayloadComponents{
		payloadWithBaseSuffix:        params.primaryComponent + baseString,
		encodedPayloadWithBaseSuffix: params.encodedComponent + baseString,
		baseSuffix:                   "//",
		encodedBaseSuffix:            "//",
		// C: var1.C + var0,
		// A: var1.A + var0,
		// B: "//",
		// D: "//",
	}
}

// createJSStringBreakoutStrategyFromOperator corresponds to Java: private static ContextualXSSTechnique lambda$createBreakOut$2(etl var0, am_ var1, String var2)
func createJSStringBreakoutStrategyFromOperator(
	builder JSStringComponentBuilder,
	params JavaScriptPayloadParams,
	operator string,
) ContextualAttackPayloadGenerator {
	// return new dff(var0.a(var2, var1));
	// etlVal.A is the method from Etl interface, equivalent to var0.a()
	payloadComponents := builder.BuildComponents(operator, params)
	return NewJSStringFromComponentsStrategy(
		payloadComponents,
	)
}

// --- Adapters for Functional Interfaces ---

// jsStringComponentBuilderAdapter implements the Etl interface using a function pointer.
type jsStringComponentBuilderAdapter struct {
	builderFunc func(baseStr string, params JavaScriptPayloadParams) JSStringPayloadComponents
}

func (e *jsStringComponentBuilderAdapter) BuildComponents(
	baseString string,
	params JavaScriptPayloadParams,
) JSStringPayloadComponents {
	return e.builderFunc(baseString, params)
}

// jsStringBreakoutStrategyFactoryAdapter implements the G41 interface, capturing Etl and Am_ for lambdaCreateBreakOut2Ch8.
type jsStringBreakoutStrategyFactoryAdapter struct {
	componentBuilder JSStringComponentBuilder
	payloadParams    JavaScriptPayloadParams
}

func (w *jsStringBreakoutStrategyFactoryAdapter) CreateStrategy(
	operator string,
) ContextualAttackPayloadGenerator { // Implements G41 interface method A(String) ContextualXSSTechnique
	return createJSStringBreakoutStrategyFromOperator(w.componentBuilder, w.payloadParams, operator)
}

// --- Private Helper Method Ported ---

// buildCoreBreakoutLogic corresponds to Java: private ContextualXSSTechnique a(etl var1, am_ var2, boolean var3)
func (receiver *JavaScriptStringBreakoutStrategy) buildCoreBreakoutLogic(
	componentBuilder JSStringComponentBuilder,
	params JavaScriptPayloadParams,
	useVariants bool,
) ContextualAttackPayloadGenerator {
	// return new c0b(new fdz(var2, var3),
	//    new gfw(new dgl(var2, var3),
	//            new ckn(ch8::lambda$createBreakOut$2), // This requires an adapter for G41
	//            new ctw(var2, var3)));

	encodedVariantStrategy := NewEncodedJSStringVariantStrategy(params, useVariants)
	semicolonInjectionStrategy := NewJavaScriptSemicolonInjectionStrategy(params, useVariants)

	// For ch8::lambda$createBreakOut$2, which is (etl, am_, String) -> ContextualXSSTechnique
	// and ckn expects g41... which is (String) -> ContextualXSSTechnique.
	// We need an adapter that implements G41 and captures etlVal and amVal.
	strategyFactoryAdapter := &jsStringBreakoutStrategyFactoryAdapter{
		componentBuilder: componentBuilder,
		payloadParams:    params,
	}
	operatorInjectionStrategy := NewJavaScriptOperatorInjectionStrategy(
		strategyFactoryAdapter,
	) // NewCkn stub takes varargs G41

	semicolonVariantStrategy := NewJSStringSemicolonVariantStrategy(params, useVariants)
	innerIteratorStrategy := NewFirstSuccessMetaStrategy(
		semicolonInjectionStrategy,
		operatorInjectionStrategy,
		semicolonVariantStrategy,
	)

	return NewSequentialMetaStrategy(encodedVariantStrategy, innerIteratorStrategy)
}

// --- Constructor Ported ---

// NewJavaScriptStringBreakoutStrategy creates a new concrete instance of Ch8.
// Original Java constructor: public ch8(String var1, def var2, boolean var3)
func NewJavaScriptStringBreakoutStrategy(
	quoteChar string,
	contentType *ContentTypeProfile,
	enableAdvancedMode bool,
) *JavaScriptStringBreakoutStrategy {
	receiver := &JavaScriptStringBreakoutStrategy{enableHtmlEntityDecoding: enableAdvancedMode}

	// am_ var4 = new am_("\"", "\"", 0); // Quote
	// paramsForQuote := Am_{C: "\"", A: "\"", B: 0}
	paramsForQuote := JavaScriptPayloadParams{primaryComponent: quoteChar, encodedComponent: quoteChar, flag: 0}

	// am_ var5 = new am_("\\\"", "\\\\\"", 64); // Escaped quote. Java: ("\\" + var1, "\\\\" + var1, 64)
	// Original ch8 constructor uses var1 (the quote string, e.g. " or ') in am_ var5, not a generic strVar1.
	// The constructor param strVar1 is the quote character itself.
	paramsForEscapedQuote := JavaScriptPayloadParams{
		primaryComponent: "\\" + quoteChar,
		encodedComponent: "\\\\" + quoteChar,
		flag:             64,
	}

	// etl var6 = ch8::lambda$new$0;
	defaultComponentBuilder := &jsStringComponentBuilderAdapter{
		builderFunc: buildJSStringComponentsDefault,
	}

	// etl var7 = ch8::lambda$new$1;
	commentSuffixComponentBuilder := &jsStringComponentBuilderAdapter{
		builderFunc: buildJSStringComponentsWithCommentSuffix,
	}

	// this.a = new gfw(this.a(var6, var4, var3), this.a(var7, var5, var3), new dw1(var2, var3));
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

// --- ContextualXSSTechnique Interface Method A Ported ---

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Ch8.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JavaScriptStringBreakoutStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// if (this.b) {
	//    var2 = var2.a(); // Calls hnx.a()
	// }
	finalProfile := profile
	if receiver.enableHtmlEntityDecoding {
		finalProfile = profile.WithHtmlEntityDecoding() // .A() is the Hnx method to change its internal state
	}

	// return this.a.a(var1, var2, var3, var4, var5, var6);
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		finalProfile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
