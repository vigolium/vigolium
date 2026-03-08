package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JSCommentTerminatorVariantStrategy implements the ContextualXSSTechnique interface.
// Original Java class: bzp
type JSCommentTerminatorVariantStrategy struct {
	variantGeneratingStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;' - In Java this was initialized with a b3r instance.
}

// createJSCommentTerminatorPayload is the Go equivalent of the static Java lambda lambda$createInjection$1
// private static PreliminaryXSSFinding lambda$createInjection$1(String var0, hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func createJSCommentTerminatorPayload(
	terminator string,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// String var7 = "#{random_string_5}" + var0 + "#{random_string_5b}";
	formattedPayload := "#{random_string_5}" + terminator + "#{random_string_5b}"
	// return var1.c().a((byte)4, var7, var2);
	return probeBuilder.WithoutSecondaryCanary().BuildFinding(byte(4), formattedPayload, profile)
}

// NewJSCommentTerminatorVariantStrategy creates a new instance of Bzp.
// Original Java constructor: public bzp(String var1, String var2, boolean var3)
func NewJSCommentTerminatorVariantStrategy(
	terminatorBase string,
	unusedString string,
	useHTMLEntityVariants bool,
) *JSCommentTerminatorVariantStrategy {
	receiver := &JSCommentTerminatorVariantStrategy{}

	// String var4 = var1 + var2; // var4 is unused in Java, so we ignore it.

	// this.a = new b3r(var1, var3, this::lambda$new$0);
	// For this::lambda$new$0, we create an adapter that implements Blw
	strategyFactory := &jsCommentTerminatorStrategyFactoryAdapter{
		parentStrategy:          receiver,
		capturedTerminatorBase:  terminatorBase,
		capturedUseVariantsFlag: useHTMLEntityVariants,
	}

	// NewB3r expects a Blw. b3r itself implements ContextualXSSTechnique.
	// The result of NewB3r is ContextualXSSTechnique, assignable to receiver.ValA
	receiver.variantGeneratingStrategy = NewHTMLEntityVariantCompositeStrategy(
		terminatorBase,
		useHTMLEntityVariants,
		strategyFactory,
	)

	return receiver
}

// createStrategyForTerminator is the Go equivalent of private ContextualXSSTechnique a(String var1) in Bzp class.
// It returns a ContextualXSSTechnique implementation that wraps lambdaCreateInjection1Bzp.
func (strategy *JSCommentTerminatorVariantStrategy) createStrategyForTerminator(
	terminator string,
) ContextualAttackPayloadGenerator {
	// return bzp::lambda$createInjection$1;
	// This means it returns a ContextualXSSTechnique whose A method will call lambdaCreateInjection1 with strVal captured.
	return &jsCommentTerminatorLambdaWrapper{capturedTerminator: terminator}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for Bzp.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JSCommentTerminatorVariantStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return this.a.a(var1, var2, var3, var4, var5, var6);
	return receiver.variantGeneratingStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}

// jsCommentTerminatorLambdaWrapper wraps the static lambdaCreateInjection1Bzp to implement ContextualXSSTechnique.
// It needs to capture the 'String var0' for the lambda.
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

// jsCommentTerminatorStrategyFactoryAdapter implements the Blw interface and captures necessary context from Bzp instance.
// This adapter is used to pass to NewB3r.
type jsCommentTerminatorStrategyFactoryAdapter struct {
	parentStrategy          *JSCommentTerminatorVariantStrategy
	capturedTerminatorBase  string // from bzp constructor var1
	capturedUseVariantsFlag bool   // from bzp constructor var3 (boolean)
}

func (adapter *jsCommentTerminatorStrategyFactoryAdapter) IsStrategyFactoryFromString() {} // Implement IsBlw for Blw interface

// CreateStrategy implements the Blw interface's CreateStrategy method.
// public interface blw { ContextualXSSTechnique a(String var1); }
// This method effectively becomes the lambda$new$0 from Java.
// private ContextualXSSTechnique lambda$new$0(String var1_cap, boolean var2_cap, String var3_arg_from_blw_call)
func (adapter *jsCommentTerminatorStrategyFactoryAdapter) CreateStrategy(
	terminatorVariant string,
) ContextualAttackPayloadGenerator {
	// Original Java: return new c0b(this.a(var3_from_blw_call), new g4h(var1_cap, var1_cap, var2_cap));
	// this.a(var3_from_blw_call) becomes adapter.bzpInstance.aInternalBzp(blwArgString)
	terminatorPayloadStrategy := adapter.parentStrategy.createStrategyForTerminator(
		terminatorVariant,
	)

	// new g4h(var1_cap, var1_cap, var2_cap)
	numericStringVariantStrategy := NewJSNumericStringVariantCompositeStrategy(
		adapter.capturedTerminatorBase,
		adapter.capturedTerminatorBase,
		adapter.capturedUseVariantsFlag,
	)

	return NewSequentialMetaStrategy(
		terminatorPayloadStrategy,
		numericStringVariantStrategy,
	) // NewC0b returns *C0b which implements ContextualXSSTechnique
}
