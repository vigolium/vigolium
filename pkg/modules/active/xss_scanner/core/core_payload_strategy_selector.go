package core

import (
	"errors"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

var proofOfConceptPayloads = []string{
	// "alert(1)",
	// "confirm(1)",
	// "prompt(1)",
	// "document.location=1",
	// "document.title=1",
	"poc",
}

type XSSPayloadStrategyCoordinator struct {
	randomProvider   *utils.RandomGenerator
	isAggressiveScan bool
	attackStepRunner AttackStepRunner
}

// NewXSSPayloadStrategyCoordinator creates a new instance.
func NewXSSPayloadStrategyCoordinator(
	randomProvider *utils.RandomGenerator,
	attackExecutor ScanExecutionManager,
	isAggressiveScan bool,
) *XSSPayloadStrategyCoordinator {
	baseAttackStepExecutor := NewAttackControllerAdapterExecutor(
		attackExecutor,
	)

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

// Parameter names are mapped for clarity in Go.
func (coordinator *XSSPayloadStrategyCoordinator) SelectAndExecuteStrategy(
	contextType ReflectionContext,
	tactic ReflectionTacticType,
	contentType *ContentTypeProfile,
	injectionPoint httpmsg.InsertionPoint,
	reflection ReflectionOccurrenceDetail,
	detector *HTTPReflectionPointDetector,
) (PotentialXSSFinding, error) {
	zap.L().Debug("Scanning with reflectionContext", zap.String("context", contextType.String()))
	pocPayloadCategoryIndex := determinePocPayloadCategory(
		coordinator.attackStepRunner,
		injectionPoint,
		tactic,
		contextType,
	)
	techniqueClassifier := NewIndexedAttackTechniqueIdentifier(
		pocPayloadCategoryIndex,
	)

	randomTagNameProvider := NewRandomHTMLTagGenerator(
		coordinator.randomProvider,
	)
	probeBuilder := NewScanProbeBuilder(
		coordinator.randomProvider,
		randomTagNameProvider,
		coordinator.attackStepRunner,
		injectionPoint,
		techniqueClassifier,
		tactic,
		coordinator.isAggressiveScan,
	)

	scanProfile := NewScanExecutionProfile(contextType)

	zap.L().Info("Select Strategy for reflectionContext", zap.String("context", contextType.String()))
	attackStrategy := selectAttackStrategyForContext(
		contextType,
		coordinator.randomProvider,
		contentType,
	)
	zap.L().Info("Found attack strategy", zap.Any("strategy", attackStrategy))

	if attackStrategy == nil {
		return nil, errors.New("no applicable strategy") // No error, just no applicable strategy
	}

	if detector == nil {
		return nil, errors.New("cannot process reflection") // No error, cannot process reflection
	}

	return attackStrategy.GeneratePayload(
		probeBuilder,
		scanProfile,
		tactic,
		contextType,
		reflection,
		detector.GetTransaction(),
	), nil
}

func selectAttackStrategyForContext(
	contextType ReflectionContext,
	randomProvider *utils.RandomGenerator,
	contentType *ContentTypeProfile,
) ContextualAttackPayloadGenerator {
	// Assuming contentTypeInfo will be non-nil if this path is reached,
	// or specific strategy constructors handle nil ContentTypeProfile.
	statedContentTypeCode := contentType.GetStatedTypeCode()

	switch contextType {
	case ReflectionContextHTMLGeneric, ReflectionContextXMLGeneric:
		if statedContentTypeCode == DefTypeXML { // DefTypeXML is const 262
			return NewXMLHTMLGenericCompositeStrategy("", false, contentType)
		}
		return NewGenericBreakoutCompositeStrategy("", false)
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

func determinePocPayloadCategory(
	stepRunner AttackStepRunner,
	injectionPoint httpmsg.InsertionPoint,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
) int {
	categoryIndex := 0

	for categoryIndex < len(proofOfConceptPayloads) {
		pocPayload := proofOfConceptPayloads[categoryIndex]
		techniqueClassifierForRunner := NewDefaultAttackTechniqueIdentifier()
		scanProfileForRunner := NewScanExecutionProfile(
			contextType,
		).withBaseCanaryComponent(pocPayload)
		// Changed AMethod to SetFInternal

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

func GetDefaultAttackTechniqueClassifier() AttackTechniqueClassifier {
	return NewIndexedAttackTechniqueIdentifier(0)
}

func GetProofOfConceptPayloads() []string {
	// Return a copy to prevent modification if necessary
	c := make([]string, len(proofOfConceptPayloads))
	copy(c, proofOfConceptPayloads)
	return c
}
