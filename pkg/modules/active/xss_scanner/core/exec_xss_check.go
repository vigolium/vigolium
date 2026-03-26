package core

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

type XSSCheckRunner struct {
	payloadModifier                       BytePayloadModifier
	randomProvider                        *utils.RandomGenerator
	requiresFollowUpForNonHTTPOrPlaintext bool
	targetInjectionPoint                  httpmsg.InsertionPoint
	httpService                           *httpmsg.Service
	httpClient                            *http.Requester
}

// NewXSSCheckRunner creates a new XSSCheckRunner instance.
func NewXSSCheckRunner(
	payloadModifier BytePayloadModifier,
	randomProvider *utils.RandomGenerator,
	requiresFollowUp bool,
	injectionPoint httpmsg.InsertionPoint,
	httpService *httpmsg.Service,
	httpClient *http.Requester,
) *XSSCheckRunner {

	return &XSSCheckRunner{
		payloadModifier:                       payloadModifier,
		randomProvider:                        randomProvider,
		requiresFollowUpForNonHTTPOrPlaintext: requiresFollowUp,
		targetInjectionPoint:                  injectionPoint,
		httpService:                           httpService,
		httpClient:                            httpClient,
	}
}

// Scan initiates XSS checks for the given injection point.
func (runner *XSSCheckRunner) Scan(
	injectionPointToFuzz httpmsg.InsertionPoint,
	currentScanFlags int,
	basePayload []byte,
	tactic ReflectionTacticType,
	targetContextType ReflectionContext,
	preparedDetector *HTTPReflectionPointDetector,
	performFollowUpRequest bool,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	var effectivePayloadUsed []byte
	var finalDetectedReflection ReflectionOccurrenceDetail
	var effectiveHTTPTransaction *utils.HTTPTransaction

	if performFollowUpRequest {

		// Send request with (basePayload + randomSuffix) and analyze the response
		followUpAnalysis := runner.sendModifiedRequestAndAnalyze(
			injectionPointToFuzz,
			profile,
			basePayload,
			tactic,
		)
		defer func() {
			if followUpAnalysis != nil {
				followUpAnalysis.ResponseTransaction.Close()
			}
		}()
		if followUpAnalysis != nil && followUpAnalysis.FoundReflection != nil {
			effectivePayloadUsed = followUpAnalysis.EffectivePayloadUsed
			finalDetectedReflection = followUpAnalysis.FoundReflection
			effectiveHTTPTransaction = followUpAnalysis.ResponseTransaction
		} else {
			// No reflection found from sendModifiedRequestAndAnalyze in followUpRequest path.
			return nil
		}
	} else { // followUpRequest is false
		if preparedDetector == nil {
			if runner.requiresFollowUpForNonHTTPOrPlaintext {
				secondRequestResult := runner.sendModifiedRequestAndAnalyze(injectionPointToFuzz, profile, basePayload, tactic)
				defer func() {
					if secondRequestResult != nil {
						secondRequestResult.ResponseTransaction.Close()
					}
				}()
				if secondRequestResult != nil && secondRequestResult.FoundReflection != nil {
					effectivePayloadUsed = secondRequestResult.EffectivePayloadUsed
					finalDetectedReflection = secondRequestResult.FoundReflection
					effectiveHTTPTransaction = secondRequestResult.ResponseTransaction
				} else {
					return nil
				}
			} else {
				return nil
			}
		} else { // preparedDetector is NOT nil
			modifiedBasePayload := basePayload
			if runner.payloadModifier != nil {
				modifiedBasePayload = runner.payloadModifier.Modify(basePayload)
			}

			// Build a matcher for the reflection context and search the prepared detector's reflections.
			matcherForPreparedDetector := profile.getAggregatedMatchCriterion()

			reflectionInPrepared := preparedDetector.FindMatchingReflection(ReflectionLocationBody, matcherForPreparedDetector)
			if reflectionInPrepared == nil && profile.targetReflectionContext != ReflectionContextHTMLGeneric {
				// Fallback: if the specific context matcher fails, try a generic HTML matcher.
				genericHTMLProfile := NewScanExecutionProfile(ReflectionContextHTMLGeneric)
				matcherForPreparedDetector = genericHTMLProfile.getAggregatedMatchCriterion()
				reflectionInPrepared = preparedDetector.FindMatchingReflection(ReflectionLocationBody, matcherForPreparedDetector)
			}

			if reflectionInPrepared != nil {
				effectivePayloadUsed = modifiedBasePayload
				finalDetectedReflection = reflectionInPrepared
				effectiveHTTPTransaction = preparedDetector.transaction
				if effectiveHTTPTransaction == nil {
					return nil
				}
			} else {
				if runner.requiresFollowUpForNonHTTPOrPlaintext {
					thirdAttemptAnalysis := runner.sendModifiedRequestAndAnalyze(injectionPointToFuzz, profile, basePayload, tactic)
					defer func() {
						if thirdAttemptAnalysis != nil {
							thirdAttemptAnalysis.ResponseTransaction.Close()
						}
					}()

					if thirdAttemptAnalysis != nil && thirdAttemptAnalysis.FoundReflection != nil {
						effectivePayloadUsed = thirdAttemptAnalysis.EffectivePayloadUsed
						finalDetectedReflection = thirdAttemptAnalysis.FoundReflection
						effectiveHTTPTransaction = thirdAttemptAnalysis.ResponseTransaction
					} else {
						return nil
					}
				} else {
					return nil
				}
			}
		}
	}

	if finalDetectedReflection == nil {
		return nil
	}
	if effectiveHTTPTransaction == nil || !effectiveHTTPTransaction.IsHasResponse() {
		return nil
	}
	if finalDetectedReflection.CoreInfo() == nil {
		return nil
	}

	finding := BuildXSSScanFinding(
		injectionPointToFuzz,
		effectivePayloadUsed,
		tactic,
		currentScanFlags,
		finalDetectedReflection.CoreInfo(),
		effectiveHTTPTransaction,
	)

	// Clear the HTTPTransaction reference in finding since we've copied all needed data
	// This allows safe cleanup of the transaction while preserving data access for callbacks
	if finding != nil {
		finding.HTTPTransaction = nil
	}

	return finding
}

func (runner *XSSCheckRunner) findReflectionWithMatcher(
	matcher ReflectionMatchCriterion,
	detector *HTTPReflectionPointDetector,
) ReflectionOccurrenceDetail {

	if detector == nil {
		return nil
	}
	foundReflection := detector.FindMatchingReflection(
		ReflectionLocationBody,
		matcher,
	)

	return foundReflection
}

func (runner *XSSCheckRunner) isReflectionWhitespaceOrControlCharsOnly(
	reflection ReflectionOccurrenceDetail,
	detector *HTTPReflectionPointDetector,
	requireDetectorValidation bool,
) bool {
	if reflection == nil {
		return false
	}
	if requireDetectorValidation {
		if detector == nil {
			return false
		}
		detectorValidationResult := detector.IsReflectionRegionWhitespaceOrControl(reflection)
		if !detectorValidationResult {
			return false
		}
	}
	return true
}

// sendModifiedRequestAndAnalyze prepares the payload, uses the FuzzPayloadManipulator, and sends the request.
func (runner *XSSCheckRunner) sendModifiedRequestAndAnalyze(
	injectionPoint httpmsg.InsertionPoint,
	profile *ScanExecutionProfile,
	basePayload []byte,
	tactic ReflectionTacticType,
) *ModifiedRequestAnalysis {
	randomSuffix := runner.randomProvider.GeneratePrefixedAlphanumeric(6)
	randomSuffixBytes := utils.StringToBytes(randomSuffix)
	payloadWithRandomSuffix := utils.CombineByteSlices(
		basePayload,
		randomSuffixBytes,
	)

	finalPayloadToSendBytes := payloadWithRandomSuffix
	if runner.payloadModifier != nil {
		finalPayloadToSendBytes = runner.payloadModifier.Modify(payloadWithRandomSuffix)
	}

	fuzzedRequestBytes := injectionPoint.BuildRequest(finalPayloadToSendBytes)

	responseTransaction, err := utils.SendAndReceive(fuzzedRequestBytes, runner.httpService, runner.httpClient)
	if err != nil {
		return nil
	}

	payloadMatcher := profile.CreateMatcherWithRandomSuffix(
		randomSuffixBytes,
	)

	responseDetector := NewHTTPReflectionPointDetector(
		responseTransaction,
		payloadMatcher,
		finalPayloadToSendBytes,
		runner.randomProvider,
	)
	if responseDetector == nil {
		responseTransaction.Close()
		return nil
	}

	profileMatcher := profile.getAggregatedMatchCriterion()
	foundReflection := runner.findReflectionWithMatcher(profileMatcher, responseDetector)

	isReflectionValid := runner.isReflectionWhitespaceOrControlCharsOnly(
		foundReflection,
		responseDetector,
		profile.requiresDetectorValidation,
	)
	if !isReflectionValid {
		responseTransaction.Close()
		return nil
	}

	analysis := &ModifiedRequestAnalysis{
		FoundReflection:      foundReflection,
		ResponseTransaction:  responseTransaction,
		EffectivePayloadUsed: finalPayloadToSendBytes,
		ResponseDetector:     responseDetector,
	}

	return analysis
}

type ModifiedRequestAnalysis struct {
	FoundReflection      ReflectionOccurrenceDetail
	ResponseTransaction  *utils.HTTPTransaction
	EffectivePayloadUsed []byte
	ResponseDetector     *HTTPReflectionPointDetector
}
