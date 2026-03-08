package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// EncodedJSStringVariantStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fdz
type EncodedJSStringVariantStrategy struct {
	variantGeneratingStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// createEncodedJSStringPayload is the Go equivalent of the static Java lambda lambda$createInjection$1
// private static PreliminaryXSSFinding lambda$createInjection$1(am_ var0, hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func createEncodedJSStringPayload(
	params JavaScriptPayloadParams,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// String var7 = "#{random_string_5}" + var0.c + "#{random_string_5b}";
	mainFormattedPayload := "#{random_string_5}" + params.primaryComponent + "#{random_string_5b}"
	// String var8 = "#{random_string_5}" + var0.a + "#{random_string_5b}";
	profilePayloadComponent := "#{random_string_5}" + params.encodedComponent + "#{random_string_5b}"

	// var2.b(var8) now returns Hnx
	finalProfile := profile.WithVariantCanaryComponent(profilePayloadComponent)
	// hgm.c().a(int).BuildBgf(byte, String, *Hnx)
	return probeBuilder.WithoutSecondaryCanary().
		WithAdditionalScanFlags(params.flag).
		BuildFinding(byte(4), mainFormattedPayload, finalProfile)
}

// encodedJSStringLambdaWrapper wraps lambdaCreateInjection1Fdz to implement ContextualXSSTechnique.
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

// aInternalFdz corresponds to private ContextualXSSTechnique a(am_ var1) in Fdz class.
func (receiver *EncodedJSStringVariantStrategy) aInternalFdz(
	amVal JavaScriptPayloadParams,
) ContextualAttackPayloadGenerator {
	// return fdz::lambda$createInjection$1;
	return &encodedJSStringLambdaWrapper{capturedParams: amVal}
}

// encodedJSStringStrategyFactoryAdapter implements the Blw interface for Fdz.
type encodedJSStringStrategyFactoryAdapter struct {
	parentStrategy                    *EncodedJSStringVariantStrategy
	capturedBaseParams                JavaScriptPayloadParams // Captured from fdz constructor's am_ var1
	capturedUseHTMLEntityVariantsFlag bool                    // Captured from fdz constructor's boolean var2
}

func (adapter *encodedJSStringStrategyFactoryAdapter) IsStrategyFactoryFromString() {} // Implement IsBlw for Blw interface

// CreateStrategy implements Blw.CreateStrategy, effectively becoming lambda$new$0 from Java.
// Java: private ContextualXSSTechnique lambda$new$0(am_ var1_cap_am, boolean var2_cap_bool, String var3_arg_from_blw_call)
// Go adapter captures var1_cap_am and var2_cap_bool.
// blwArgString corresponds to var3_arg_from_blw_call.
func (adapter *encodedJSStringStrategyFactoryAdapter) CreateStrategy(
	payloadComponent string,
) ContextualAttackPayloadGenerator {
	// return this.a(new am_(var3_arg_from_blw_call, var1_cap_am.a, var1_cap_am.b));
	modifiedParams := JavaScriptPayloadParams{
		primaryComponent: payloadComponent,                            // var3_arg_from_blw_call
		encodedComponent: adapter.capturedBaseParams.encodedComponent, // var1_cap_am.a
		flag:             adapter.capturedBaseParams.flag,             // var1_cap_am.b
	}
	return adapter.parentStrategy.aInternalFdz(modifiedParams)
}

// NewEncodedJSStringVariantStrategy creates a new instance of Fdz.
// Original Java constructor: public fdz(am_ var1, boolean var2)
func NewEncodedJSStringVariantStrategy(
	baseParams JavaScriptPayloadParams,
	useHTMLEntityVariants bool,
) *EncodedJSStringVariantStrategy {
	receiver := &EncodedJSStringVariantStrategy{}

	// this.a = new b3r(var1.c, var2, this::lambda$new$0);
	strategyFactory := &encodedJSStringStrategyFactoryAdapter{
		parentStrategy:                    receiver,
		capturedBaseParams:                baseParams,
		capturedUseHTMLEntityVariantsFlag: useHTMLEntityVariants, // This was unused by lambda$new$0 in Java but captured by signature
	}

	// NewB3r returns *B3r which should implement ContextualXSSTechnique.
	receiver.variantGeneratingStrategy = NewHTMLEntityVariantCompositeStrategy(
		baseParams.primaryComponent,
		useHTMLEntityVariants,
		strategyFactory,
	)

	return receiver
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Fdz.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *EncodedJSStringVariantStrategy) GeneratePayload(
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
