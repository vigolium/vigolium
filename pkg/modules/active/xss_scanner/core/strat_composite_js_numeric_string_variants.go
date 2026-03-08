package core

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// JSNumericStringVariantCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: g4h
type JSNumericStringVariantCompositeStrategy struct {
	variantGeneratingStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// createJSNumericStringPayload is the Go equivalent of the static Java lambda
// private static PreliminaryXSSFinding lambda$createInjection$1(String var0_payload, String var1_captured_constructor_var2, hgm var2, hnx var3, byte var4, byte var5, DetectedReflection var6, byte[] var7)
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
	// Payload for the main part (using payload from BLW)
	mainFormattedPayload := fmt.Sprintf(
		"#{random_numeric_string_5}%s#{poc}//#{random_numeric_string_3}",
		basePayload,
	)
	// Payload for the Hnx.B part (using captured constructorVar2)
	profilePayloadComponent := fmt.Sprintf(
		"#{random_numeric_string_5}%s#{poc}//#{random_numeric_string_3}",
		constructorArg,
	)

	// var3.b(payload2) now returns Hnx
	finalProfile := profile.WithVariantCanaryComponent(profilePayloadComponent)
	return probeBuilder.WithAdditionalScanFlags(4).
		BuildFinding(byte(3), mainFormattedPayload, finalProfile)
}

// jsNumericStringLambdaWrapper wraps lambdaCreateInjection1G4h to implement ContextualXSSTechnique.
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

// aInternalG4h corresponds to private ContextualXSSTechnique a(String var1, String var2) in G4h class.
// var1 is capturedConstructorVar2, var2 is payloadFromBlw
func (receiver *JSNumericStringVariantCompositeStrategy) aInternalG4h(
	capturedConstructorVar2 string,
	payloadFromBlw string,
) ContextualAttackPayloadGenerator {
	// return g4h::lambda$createInjection$1; (which needs to capture payloadFromBlw and capturedConstructorVar2)
	return &jsNumericStringLambdaWrapper{
		capturedBasePayload:    payloadFromBlw,
		capturedConstructorArg: capturedConstructorVar2,
	}
}

// jsNumericStringStrategyFactoryAdapter implements the Blw interface for G4h.
type jsNumericStringStrategyFactoryAdapter struct {
	parentStrategy         *JSNumericStringVariantCompositeStrategy
	capturedConstructorArg string // Captured from g4h constructor's var2 (String)
}

func (adapter *jsNumericStringStrategyFactoryAdapter) IsStrategyFactoryFromString() {} // Implement IsBlw for Blw interface

// CreateStrategy implements Blw.CreateStrategy, effectively becoming lambda$new$0 from Java.
// Java: private ContextualXSSTechnique lambda$new$0(String var1_captured_constructor_var2, String var2_payload_from_blw)
func (adapter *jsNumericStringStrategyFactoryAdapter) CreateStrategy(
	payloadFromBlw string,
) ContextualAttackPayloadGenerator {
	// return this.a(var1_captured_constructor_var2, var2_payload_from_blw);
	return adapter.parentStrategy.aInternalG4h(adapter.capturedConstructorArg, payloadFromBlw)
}

// NewJSNumericStringVariantCompositeStrategy creates a new instance of G4h.
// Original Java constructor: public g4h(String var1, String var2, boolean var3)
func NewJSNumericStringVariantCompositeStrategy(
	variantBase string,
	constructorArg string,
	useHTMLEntityVariants bool,
) *JSNumericStringVariantCompositeStrategy {
	receiver := &JSNumericStringVariantCompositeStrategy{}

	// this.a = new b3r(var1, var3, this::lambda$new$0);
	strategyFactory := &jsNumericStringStrategyFactoryAdapter{
		parentStrategy:         receiver,
		capturedConstructorArg: constructorArg,
	}

	// NewB3r returns *B3r which should implement ContextualXSSTechnique.
	receiver.variantGeneratingStrategy = NewHTMLEntityVariantCompositeStrategy(
		variantBase,
		useHTMLEntityVariants,
		strategyFactory,
	)
	return receiver
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class G4h.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
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
