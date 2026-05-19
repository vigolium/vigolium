package core

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

type SSTIScanner struct {
	strategyCoordinator *XSSPayloadStrategyCoordinator
	injectionPoint      httpmsg.InsertionPoint
	findingHandler      func(reflectionContextType ReflectionContext, result PotentialXSSFinding)
	ignoredContexts     map[ReflectionContext]struct{}
	sstiPayload         *PayloadModificationContext
	randomProvider      *utils.RandomGenerator
	httpService         *httpmsg.Service
	httpClient          *http.Requester
}

// NewSSTIScanner creates a new SSTIScanner.
func NewSSTIScanner(
	injectionPoint httpmsg.InsertionPoint,
	sstiPayload *PayloadModificationContext,
	ignoredContexts []ReflectionContext,
	findingHandler func(ReflectionContext, PotentialXSSFinding),
	randomProvider *utils.RandomGenerator,
	isAggressive bool,
	httpService *httpmsg.Service,
	httpClient *http.Requester,
) *SSTIScanner {

	payloadModifier := NewContextualPrefixPayloadTransformer(sstiPayload)

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
		isAggressive,
	)

	ignoredMap := make(map[ReflectionContext]struct{})
	for _, b := range ignoredContexts {
		ignoredMap[b] = struct{}{}
	}

	return &SSTIScanner{
		strategyCoordinator: strategyCoord,
		injectionPoint:      injectionPoint,
		findingHandler:      findingHandler,
		ignoredContexts:     ignoredMap,
		sstiPayload:         sstiPayload,
		randomProvider:      randomProvider,
		httpService:         httpService,
		httpClient:          httpClient,
	}
}

// PerformSSTIChecks performs SSTI checks, initiating the SSTI scan.
func (s *SSTIScanner) PerformSSTIChecks() {
	s.performSimpleCheck()
}

// performSimpleCheck performs SSTI checks
func (s *SSTIScanner) performSimpleCheck() {
	detector, err := s.getReflectionDetector()
	if err != nil {
		zap.L().Debug("SSTI: could not get reflection detector", zap.Error(err))
		return
	}
	if detector == nil {
		return
	}
	defer detector.GetTransaction().Close()

	bodyReflections := detector.GetReflections(ReflectionLocationBody)
	for _, reflection := range bodyReflections {
		coreInfo := reflection.CoreInfo()
		if coreInfo == nil {
			continue
		}

		if _, ignored := s.ignoredContexts[coreInfo.ContextType()]; ignored {
			continue
		}

		if coreInfo.StartIndex() == -1 { // from `var4.a().c != -1`
			continue
		}

		found := s.runStrategyForReflection(reflection, detector.GetContentTypeProfile(), detector)
		if found {
			return
		}
	}
}

// getReflectionDetector creates a reflection detector
func (s *SSTIScanner) getReflectionDetector() (*HTTPReflectionPointDetector, error) {
	// This function mimics that by sending a request with the SSTI payload to find reflections.

	payloadBytes := s.sstiPayload.GetPrefixedPrimaryData()

	fuzzedRequestBytes := s.injectionPoint.BuildRequest(payloadBytes)
	httpTransaction, err := utils.SendAndReceive(fuzzedRequestBytes, s.httpService, s.httpClient)
	if err != nil {
		return nil, err
	}

	// So the matcher is only for the main payload, not prefix.
	matcher := NewSimpleBytePatternMatcher(s.sstiPayload.primaryData)

	detector := NewHTTPReflectionPointDetector(
		httpTransaction,
		matcher,
		payloadBytes, // The full payload sent
		s.randomProvider,
	)

	if detector == nil {
		if httpTransaction != nil {
			httpTransaction.Close()
		}
		return nil, fmt.Errorf("could not create detector")
	}
	if detector.GetContentTypeProfile() == nil {
		detector.GetTransaction().Close()
		return nil, fmt.Errorf("could not get content type from detector")
	}

	return detector, nil
}

// runStrategyForReflection runs strategy for a given reflection
func (s *SSTIScanner) runStrategyForReflection(
	reflection ReflectionOccurrenceDetail,
	contentType *ContentTypeProfile,
	detector *HTTPReflectionPointDetector,
) bool {
	contextType := reflection.CoreInfo().ContextType()

	finding, err := s.strategyCoordinator.SelectAndExecuteStrategy(
		contextType,
		TacticAppend,
		contentType,
		s.injectionPoint,
		reflection,
		detector,
	)

	if err != nil {
		zap.L().Error("SSTI: error during strategy execution", zap.Error(err))
		return false
	}

	if finding != nil {
		s.findingHandler(contextType, finding)
		return true
	}

	return false
}
