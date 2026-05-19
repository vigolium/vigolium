package core

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

type XSSScanningCoordinator struct {
	strategyCoordinator *XSSPayloadStrategyCoordinator
	injectionPoint      httpmsg.InsertionPoint
	randomProvider      *utils.RandomGenerator
	findingHandler      func(reflectionContextType ReflectionContext, result PotentialXSSFinding)
	httpService         *httpmsg.Service // HTTP service for request execution
	httpClient          *http.Requester

	reflectionDetectorCache map[ReflectionTacticType]*HTTPReflectionPointDetector
}

func NewXSSScanningCoordinator(
	injectionPoint httpmsg.InsertionPoint,
	payloadModifier BytePayloadModifier,
	findingHandler func(ReflectionContext, PotentialXSSFinding),
	httpService *httpmsg.Service,
	httpClient *http.Requester,
) *XSSScanningCoordinator {
	randomProvider := utils.NewRandomGenerator()
	checkRunner := NewXSSCheckRunner(
		payloadModifier,
		randomProvider,
		true,
		injectionPoint,
		httpService,
		httpClient,
	)
	strategyCoord := NewXSSPayloadStrategyCoordinator(
		randomProvider,
		checkRunner,
		false,
	)

	coordinator := &XSSScanningCoordinator{
		strategyCoordinator:     strategyCoord,
		injectionPoint:          injectionPoint,
		randomProvider:          randomProvider,
		findingHandler:          findingHandler,
		httpService:             httpService,
		httpClient:              httpClient,
		reflectionDetectorCache: make(map[ReflectionTacticType]*HTTPReflectionPointDetector, 2),
	}

	return coordinator
}

func (g *XSSScanningCoordinator) PerformXSSChecks() {
	defer func() {
		for _, detector := range g.reflectionDetectorCache {
			if detector != nil && detector.GetTransaction() != nil {
				detector.GetTransaction().Close()
			}
		}
	}()

	appendTacticDetector, err := g.getReflectionDetectorForTactic(TacticAppend)
	if err != nil {
		zap.L().Debug("error in getReflectionDetectorForTactic", zap.Error(err))
		return
	}

	if appendTacticDetector.GetContentTypeProfile() != nil {
		statedContentTypeCode := appendTacticDetector.GetContentTypeProfile().GetStatedTypeCode()
		zap.L().Debug("statedType", zap.String("type", appendTacticDetector.GetContentTypeProfile().String()))
		if statedContentTypeCode != DefTypeHTML && statedContentTypeCode != DefTypeXML {
			return
		}
		// inferredType := appendReflectionDetector.GetResponseDefinition().GetG()
		// isScriptContext := (statedType == DefTypeScript || inferredType == DefTypeScript)

		// isHtmlOrXmlContext := (statedType == DefTypeHTML || inferredType == DefTypeHTML ||
		// 	statedType == DefTypeXML || inferredType == DefTypeXML)

		// if !isScriptContext && !isHtmlOrXmlContext {
		// 	return
		// }
	}

	if appendTacticDetector.HasBodyReflections() &&
		len(appendTacticDetector.GetReflections(ReflectionLocationBody)) > 0 {

		bodyReflectionDetails := appendTacticDetector.GetReflections(ReflectionLocationBody)

		for _, reflectionDetail := range bodyReflectionDetails {
			zap.L().Debug("bodyReflections context",
				zap.String("context", reflectionDetail.CoreInfo().contextType.String()))
			// log.Debugf(
			// 	"snippet: %s",
			// 	string(
			// 		appendReflectionDetector.GetHttpRequestResponse().GetResponseBody()[detected.A().ReflectionStartInInput:detected.A().ReflectionEndInInput],
			// 	),
			// )
			isXSSFound, err := g.executeSingleCheck(
				TacticAppend,
				appendTacticDetector,
				reflectionDetail,
			)
			if err != nil {
				continue
			}

			// TODO: Skipping replace tactic for now since append is sufficient
			// if !isXSSFound && g.isSpecialContext(reflectionDetail.CoreInfo().contextType) {
			// 	replaceTacticDetector, err := g.getReflectionDetectorForTactic(TacticReplace)
			// 	if err != nil {
			// 		continue
			// 	}

			// 	_, err = g.executeSingleCheck(
			// 		TacticReplace,
			// 		replaceTacticDetector,
			// 		reflectionDetail,
			// 	)
			// 	if err != nil {
			// 		continue
			// 	}

			// }
			if isXSSFound {
				return
			}
		}
	}
}

func (coordinator *XSSScanningCoordinator) PerformSSTIChecks(thoroughScan bool) {
	sstiPayloadProvider := NewSSTIPayloadProvider(coordinator.randomProvider, thoroughScan)

	for _, sstiPayload := range sstiPayloadProvider.Payloads() {
		// For now, we will use an empty list.
		var ignoredContexts []ReflectionContext

		// isAggressiveScan is false, similar to the main XSS scanner setup.
		isAggressive := true

		sstiScanner := NewSSTIScanner(
			coordinator.injectionPoint,
			sstiPayload,
			ignoredContexts,
			coordinator.findingHandler,
			coordinator.randomProvider,
			isAggressive,
			coordinator.httpService,
			coordinator.httpClient,
		)

		sstiScanner.PerformSSTIChecks()
	}
}

func (coordinator *XSSScanningCoordinator) getReflectionDetectorForTactic(
	tactic ReflectionTacticType,
) (*HTTPReflectionPointDetector, error) {
	if coordinator.reflectionDetectorCache != nil &&
		coordinator.reflectionDetectorCache[tactic] != nil {
		return coordinator.reflectionDetectorCache[tactic], nil
	}

	fuzzedRequestBytes, payloadString := coordinator.prepareFuzzingRequest(tactic)
	httpTransaction, err := utils.SendAndReceive(fuzzedRequestBytes, coordinator.httpService, coordinator.httpClient)
	if err != nil {
		return nil, err
	}

	payloadMatcher := NewSimpleBytePatternMatcher([]byte(payloadString))

	detector := NewHTTPReflectionPointDetector(
		httpTransaction,
		payloadMatcher,
		[]byte(payloadString),
		coordinator.randomProvider,
	)
	contentTypeInfo := detector.GetContentTypeProfile()
	if contentTypeInfo == nil {
		httpTransaction.Close()
		return nil, fmt.Errorf("content type info is nil")
	}

	coordinator.reflectionDetectorCache[tactic] = detector
	return detector, nil
}

func (coordinator *XSSScanningCoordinator) executeSingleCheck(
	tactic ReflectionTacticType,
	detector *HTTPReflectionPointDetector,
	reflectionDetail ReflectionOccurrenceDetail,
) (bool, error) {
	// APPEND
	contextType := reflectionDetail.CoreInfo().contextType
	finding, err := coordinator.strategyCoordinator.SelectAndExecuteStrategy(
		contextType,
		tactic,
		detector.GetContentTypeProfile(),
		coordinator.injectionPoint,
		reflectionDetail,
		detector,
	)
	if err != nil {
		zap.L().Error("error in performSingleCheck", zap.Error(err))
		return false, err
	}
	if finding == nil {
		// log.Errorf("result is nil")
		return false, nil
	}
	coordinator.findingHandler(contextType, finding)
	return true, nil
}

func (coordinator *XSSScanningCoordinator) prepareFuzzingRequest(
	tactic ReflectionTacticType,
) ([]byte, string) {
	var payloadString string
	randomSuffix := coordinator.randomProvider.GeneratePrefixedAlphanumeric(6)
	originalValue := coordinator.injectionPoint.BaseValue()
	if tactic == TacticAppend {
		payloadString = originalValue + randomSuffix
	} else {
		payloadString = randomSuffix
	}

	fuzzedRequestBytes := coordinator.injectionPoint.BuildRequest([]byte(payloadString))
	return fuzzedRequestBytes, payloadString
}
