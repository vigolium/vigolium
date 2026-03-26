package core

import (
	"errors"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// proofOfConceptPayloads corresponds to private static final String[] c in fn0.java
var proofOfConceptPayloads = []string{
	// "alert(1)",
	// "confirm(1)",
	// "prompt(1)",
	// "document.location=1",
	// "document.title=1",
	"poc",
}

// XSSPayloadStrategyCoordinator is the Go equivalent of the Java class burp.fn0.
type XSSPayloadStrategyCoordinator struct {
	randomProvider   *utils.RandomGenerator // Corresponds to private final ou b;
	isAggressiveScan bool                   // Corresponds to private final boolean a;
	attackStepRunner AttackStepRunner       // Corresponds to private final i2j d;
}

// NewXSSPayloadStrategyCoordinator creates a new instance of Fn0.
// Corresponds to public fn0(ou var1, f4x var2, boolean var3)
func NewXSSPayloadStrategyCoordinator(
	randomProvider *utils.RandomGenerator,
	attackExecutor ScanExecutionManager,
	isAggressiveScan bool,
) *XSSPayloadStrategyCoordinator {
	// ixv var4 = new ixv(var2);
	baseAttackStepExecutor := NewAttackControllerAdapterExecutor(
		attackExecutor,
	) // Assume NewIxv returns a type that implements I2j

	// this.d = new gg3(var4, new ihj(var4), new frz(var4), new hk9(var4));
	// Ensure NewIhj, NewFrz, NewHk9 accept I2j and return I2j
	// Ensure NewGg3 accepts variadic I2j and returns I2j
	chainedAttackStepRunner := NewIteratingAttackStepExecutor(
		baseAttackStepExecutor,
		NewURLEncodingAwareAttackStepExecutor(baseAttackStepExecutor),
		NewEncodingMode1AttackStepExecutor(baseAttackStepExecutor),
		NewEncodingMode2AttackStepExecutor(baseAttackStepExecutor),
	)

	return &XSSPayloadStrategyCoordinator{
		randomProvider:   randomProvider,
		isAggressiveScan: isAggressiveScan,
		attackStepRunner: chainedAttackStepRunner,
	}
}

// A is the Go equivalent of the Java method:
// public bgf a(byte var1, ll var2, def var3, bno var4, eqx var5, crp var6)
// Parameter names are mapped for clarity in Go.
func (coordinator *XSSPayloadStrategyCoordinator) SelectAndExecuteStrategy(
	contextType ReflectionContext, // var1
	tactic ReflectionTacticType, // var2
	contentType *ContentTypeProfile, // var3
	injectionPoint httpmsg.InsertionPoint, // var4
	reflection ReflectionOccurrenceDetail, // var5
	detector *HTTPReflectionPointDetector, // var6
) (PotentialXSSFinding, error) { // Added error return for Go idiom, though original Java doesn't throw checked exceptions here.
	zap.L().Debug("Scanning with reflectionContext", zap.String("context", contextType.String()))
	// ekv var7 = new ekv(a(this.d, var4, var2, var1));
	pocPayloadCategoryIndex := determinePocPayloadCategory(
		coordinator.attackStepRunner,
		injectionPoint,
		tactic,
		contextType,
	)
	techniqueClassifier := NewIndexedAttackTechniqueIdentifier(
		pocPayloadCategoryIndex,
	) // NewEkv should return *Ekv which implements Cgv

	// hgm var8 = new hgm(this.b, new d8v(this.b), this.d, var4, var7, var2, this.a);
	randomTagNameProvider := NewRandomHTMLTagGenerator(
		coordinator.randomProvider,
	) // D8v implements Fen
	probeBuilder := NewScanProbeBuilder(
		coordinator.randomProvider,
		randomTagNameProvider,
		coordinator.attackStepRunner,
		injectionPoint,
		techniqueClassifier,
		tactic,
		coordinator.isAggressiveScan,
	) // NewHgmImpl is the main constructor

	// hnx var9 = new hnx(var1);
	scanProfile := NewScanExecutionProfile(contextType)

	// d3b var10 = a(var1, this.b, var3);
	zap.L().Info("Select Strategy for reflectionContext", zap.String("context", contextType.String()))
	attackStrategy := selectAttackStrategyForContext(
		contextType,
		coordinator.randomProvider,
		contentType,
	)
	zap.L().Info("Found D3b Strategy", zap.Any("strategy", attackStrategy))

	if attackStrategy == nil {
		return nil, errors.New("no applicable strategy") // No error, just no applicable strategy
	}

	if detector == nil {
		return nil, errors.New("cannot process reflection") // No error, cannot process reflection
	}

	// return var6 == null ? null : var10.a(var8, var9, var2.a(), var1, var5, var6.a((byte)2));
	// llReflectionTypeAsByte := reflectionType.A() // ll.A() returns byte
	// payloadBytesForD3b := reflectionProcessor.AByteReturnBytes(
	// 2,
	// ) // crp.AByteReturnBytes(byte) returns []byte
	// payloadBytesForD3b := reflectionProcessor.GetContentBytes(ReflectionLocationBody)

	return attackStrategy.GeneratePayload(
		probeBuilder,
		scanProfile,
		tactic,
		contextType,
		reflection,
		detector.GetTransaction(),
	), nil
}

// selectAttackStrategyForContext is the Go equivalent of:
// private static d3b a(byte var0, ou var1, def var2)
func selectAttackStrategyForContext(
	contextType ReflectionContext,
	randomProvider *utils.RandomGenerator,
	contentType *ContentTypeProfile,
) ContextualAttackPayloadGenerator {
	// Ensure contentTypeInfo is not nil before accessing GetE(), as Java could have NPE.
	// If it can be nil and that's a valid state leading to a default D3b strategy not
	// depending on contentTypeInfo, that logic would need to be here.
	// For now, assuming contentTypeInfo will be non-nil if this path is reached,
	// or specific D3b constructors handle nil Def.
	statedContentTypeCode := contentType.GetStatedTypeCode()

	switch contextType {
	case ReflectionContextHTMLGeneric, ReflectionContextXMLGeneric:
		if statedContentTypeCode == DefTypeXML { // DefTypeXML is const 262
			return NewXMLHTMLGenericCompositeStrategy("", false, contentType)
		}
		return NewGenericBreakoutCompositeStrategy("", false)
	// Case 1 is missing in Java, 'default' handles it by assertion.
	case 1:
		return nil
	case ReflectionContextHTMLTagCloseAndInject,
		ReflectionContextHTMLAttributeName,
		ReflectionContextHTMLAttributeValueUnquotedBreakout:
		return NewTagAttributeUnquotedCompositeStrategy()
	case ReflectionContextHTMLAttributeValueDQBreakout:
		return NewQuotedAttributeBreakoutStrategy("\"")
	case ReflectionContextHTMLAttributeValueSQBreakout:
		return NewQuotedAttributeBreakoutStrategy("'")
	case ReflectionContextHTMLAttributeValueBTBreakout:
		return NewQuotedAttributeBreakoutStrategy("`")
	case ReflectionContextJSInURLAttributeDQ:
		return NewJavaScriptInURLAttributeStrategy(randomProvider, contentType, "\"")
	case ReflectionContextJSInURLAttributeSQ:
		return NewJavaScriptInURLAttributeStrategy(randomProvider, contentType, "'")
	case ReflectionContextJSInURLAttributeBT:
		return NewJavaScriptInURLAttributeStrategy(randomProvider, contentType, "`")
	case ReflectionContextJSInUnquotedURLAttribute:
		return NewJSInUnquotedURLAttributeCompositeStrategy(randomProvider, contentType)
	case ReflectionContextJSInEventHandlerDQ:
		return NewJavaScriptInEventHandlerStrategy(contentType, "\"")
	case ReflectionContextJSInEventHandlerSQ:
		return NewJavaScriptInEventHandlerStrategy(contentType, "'")
	case ReflectionContextJSInEventHandlerBT:
		return NewJavaScriptInEventHandlerStrategy(contentType, "`")
	case ReflectionContextJSInHTMLTagGeneric:
		return NewJSInHTMLGenericCompositeStrategy(contentType)
	case ReflectionContextJSStringDQBreakout:
		return NewJavaScriptStringBreakoutStrategy("\"", contentType, false)
	case ReflectionContextJSStringSQBreakout:
		return NewJavaScriptStringBreakoutStrategy("'", contentType, false)
	case ReflectionContextJSCodeStatement:
		return NewJavaScriptStatementCompositeStrategy()
	case ReflectionContextHTMLAfterXMPClose:
		return NewSpecificTagBreakoutCompositeStrategy("xmp", 6)
	case ReflectionContextHTMLAfterNoscriptClose:
		return NewSpecificTagBreakoutCompositeStrategy("noscript", 7)
	case ReflectionContextHTMLAfterTitleClose:
		return NewSpecificTagBreakoutCompositeStrategy("title", 10)
	case ReflectionContextHTMLCommentBreakout:
		return NewHTMLCommentBreakoutCompositeStrategy()
	case ReflectionContextJSLineComment:
		return NewJavaScriptCommentBreakoutStrategy("\n", contentType, false)
	case ReflectionContextJSBlockComment:
		return NewJavaScriptCommentBreakoutStrategy("*/", contentType, false)
	default:
		return nil
	}
}

// determinePocPayloadCategory is the Go equivalent of:
// private static int a(i2j var0, bno var1, ll var2, byte var3)
func determinePocPayloadCategory(
	stepRunner AttackStepRunner,
	injectionPoint httpmsg.InsertionPoint,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
) int {
	categoryIndex := 0
	// String[] var10000 = hgm.b(); // In Go, static field access is direct or via getter
	// hgmStaticBArray := HgmStaticB() // This was used in original Java for loop control, but seems to be always null if not set externally.
	// The loop control `if (var4 != null) { break; }` (where var4 is hgm.b()) in Java means if hgm.b() is *not* null, it breaks after first iteration.
	// If hgm.b() *is* null, it iterates all payloads.
	// Let's assume HgmStaticB() might return nil to mimic. If Hgm has state, this changes.
	// For now, porting the loop as if it iterates all payloads unless hgmStaticB is non-nil.
	// The provided hgm.java has `static { b(null); }`, so hgm.b() returns null, loop runs fully.

	for categoryIndex < len(proofOfConceptPayloads) {
		pocPayload := proofOfConceptPayloads[categoryIndex]
		techniqueClassifierForRunner := NewDefaultAttackTechniqueIdentifier() // Implements Cgv
		scanProfileForRunner := NewScanExecutionProfile(
			contextType,
		).withBaseCanaryComponent(pocPayload)
		// Changed AMethod to SetFInternal

		// bgf var8 = var0.a(var1, 0, var7, var2, (byte)0, new hqy(), false, new hnx(var3).a(var7));
		// Parameters for I2j.A: bnoVal, intCVal, formattedPayload, llVal, typeByte, cgvVal, boolHVal, finalHnx
		findingResult := stepRunner.RunAttackStep(
			injectionPoint,
			0,
			pocPayload,
			tactic,
			0,
			techniqueClassifierForRunner,
			false,
			scanProfileForRunner,
		)

		if findingResult != nil {
			return categoryIndex
		}
		categoryIndex++

	}
	return 0
}

// GetDefaultAttackTechniqueClassifier is the Go equivalent of: public static cgv a()
func GetDefaultAttackTechniqueClassifier() AttackTechniqueClassifier {
	return NewIndexedAttackTechniqueIdentifier(0)
}

// GetProofOfConceptPayloads is the Go equivalent of: static String[] b()
func GetProofOfConceptPayloads() []string {
	// Return a copy to prevent modification if necessary
	c := make([]string, len(proofOfConceptPayloads))
	copy(c, proofOfConceptPayloads)
	return c
}
