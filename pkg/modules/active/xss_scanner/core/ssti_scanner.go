package core

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// SSTIScanner is the Go equivalent of cf3.java, responsible for SSTI checks.
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

// PerformSSTIChecks corresponds to cf3.c(), initiating the SSTI scan.
func (s *SSTIScanner) PerformSSTIChecks() {
	// Corresponds to the cf3.a() path, which is the simpler check.
	s.performSimpleCheck()
}

// performSimpleCheck corresponds to cf3.a()
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

// getReflectionDetector corresponds to cf3.a(byte[], byte[])
func (s *SSTIScanner) getReflectionDetector() (*HTTPReflectionPointDetector, error) {
	// In cf3, it does `new ger(...)`. This seems to create a detector from scratch.
	// This function mimics that by sending a request with the SSTI payload to find reflections.

	payloadBytes := s.sstiPayload.GetPrefixedPrimaryData()

	fuzzedRequestBytes := s.injectionPoint.BuildRequest(payloadBytes)
	httpTransaction, err := utils.SendAndReceive(fuzzedRequestBytes, s.httpService, s.httpClient)
	if err != nil {
		return nil, err
	}

	// In cf3, it uses e8u.a(var2), which is NewSimpleBytePatternMatcher(d2.e).
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

// runStrategyForReflection corresponds to the lambda in cf3.a(eqx, def, big, crp)
func (s *SSTIScanner) runStrategyForReflection(
	reflection ReflectionOccurrenceDetail,
	contentType *ContentTypeProfile,
	detector *HTTPReflectionPointDetector,
) bool {
	contextType := reflection.CoreInfo().ContextType()

	finding, err := s.strategyCoordinator.SelectAndExecuteStrategy(
		contextType,
		LlAppend, // cf3 always uses ll.APPEND
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
