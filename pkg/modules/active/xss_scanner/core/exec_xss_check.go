package core

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// XSSCheckRunner is the Go equivalent of f9n.java
type XSSCheckRunner struct {
	payloadModifier                       BytePayloadModifier
	randomProvider                        *utils.RandomGenerator
	requiresFollowUpForNonHTTPOrPlaintext bool
	targetInjectionPoint                  httpmsg.InsertionPoint
	httpService                           *httpmsg.Service
	httpClient                            *http.Requester
}

// NewXSSCheckRunner creates a new F9n instance.
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

// Scan is the primary method for f9n, initiating XSS checks.
func (runner *XSSCheckRunner) Scan(
	// initialHttpRequest *http.Request,
	injectionPointToFuzz httpmsg.InsertionPoint, // Changed from bnoInsertionPoint
	currentScanFlags int,
	basePayload []byte,
	tactic ReflectionTacticType,
	targetContextType ReflectionContext,
	preparedDetector *HTTPReflectionPointDetector,
	performFollowUpRequest bool,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	var effectivePayloadUsed []byte
	// var finalB5kForKResult *B5k // Không cần lưu trữ B5k cuối cùng ở đây nữa, vì KResult sẽ lấy thông tin từ finalDetectedReflection và finalHttpTransaction
	var finalDetectedReflection ReflectionOccurrenceDetail
	var effectiveHTTPTransaction *utils.HTTPTransaction

	if performFollowUpRequest {

		// Gửi request với (basePayloadToFuzz + randomSuffix)
		// doModifiedRequestAndAnalyze sẽ tự tạo B5k từ response của nó.
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
			// finalB5kForKResult = d14Result.B5k
			finalDetectedReflection = followUpAnalysis.FoundReflection
			effectiveHTTPTransaction = followUpAnalysis.ResponseTransaction
		} else {
			// log.Println("[DEBUG F9n Scan] No reflection found from doModifiedRequestAndAnalyze in followUpRequest path.")
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
					// finalB5kForKResult = d14Result.B5k
					finalDetectedReflection = secondRequestResult.FoundReflection
					effectiveHTTPTransaction = secondRequestResult.ResponseTransaction
				} else {
					return nil
				}
			} else {
				return nil
			}
		} else { // preparedB5k is NOT nil
			modifiedBasePayload := basePayload
			if runner.payloadModifier != nil {
				modifiedBasePayload = runner.payloadModifier.Modify(basePayload)
			}

			// Hnx được truyền vào đã được cấu hình bởi lớp gọi (gus) dựa trên preparedB5k.CDef()
			// và reflectionContextTypeForHnx.
			// Matcher sẽ tìm kiếm context phù hợp trong các reflection đã có của preparedB5k.
			// Lưu ý: preparedB5k.payloadUsedInErwLogic phải là tranformedBasePayload để HPO.Canary có ý nghĩa.
			// Nếu preparedB5k được tạo từ một request khác (ví dụ request force HTML),
			// thì eqxInPrepared.A().Canary sẽ là payload của request đó, không phải tranformedBasePayload.
			// Điều này cần được xử lý cẩn thận ở lớp gọi khi tạo KResult.
			// Hiện tại FruBuildKResult sẽ dùng Canary từ Eqx được tìm thấy.
			matcherForPreparedDetector := profile.getAggregatedMatchCriterion() // DInternal tạo matcher dựa trên hnx.reflectionContext

			reflectionInPrepared := preparedDetector.FindMatchingReflection(ReflectionLocationBody, matcherForPreparedDetector) // Hoặc Header
			if reflectionInPrepared == nil && profile.targetReflectionContext != ReflectionContextHTMLGeneric {                 // Fallback to generic if specific fails
				// This is a heuristic. Java's fn0 has complex D3b selection.
				// Here, if specific HNX context matcher fails, try a generic HTML matcher.
				// This assumes hnx passed in had a specific context.
				genericHTMLProfile := NewScanExecutionProfile(ReflectionContextHTMLGeneric) // 19 is XML_GENERIC / general HTML
				matcherForPreparedDetector = genericHTMLProfile.getAggregatedMatchCriterion()
				reflectionInPrepared = preparedDetector.FindMatchingReflection(ReflectionLocationBody, matcherForPreparedDetector)
			}

			if reflectionInPrepared != nil {
				effectivePayloadUsed = modifiedBasePayload // Payload mà chúng ta đã cố gắng tìm
				finalDetectedReflection = reflectionInPrepared
				effectiveHTTPTransaction = preparedDetector.transaction // Transaction mà từ đó preparedB5k được tạo
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
	if finalDetectedReflection.CoreInfo() == nil { // Double check HPO is not nil
		return nil
	}

	// Tạo KFindingBuilder
	finding := BuildXSSScanFinding(
		injectionPointToFuzz, // fuzzParam mà f9n đã sử dụng
		effectivePayloadUsed, // payload thực tế đã gửi (finalPayloadUsed từ f9n)
		tactic,               // llVal từ f9n
		currentScanFlags,     // scanFlags từ f9n
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
	) // Assuming context 2 (body)

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

	// **** USER'S FUZZING LOGIC CALL ****
	fuzzedRequestBytes := injectionPoint.BuildRequest(finalPayloadToSendBytes)

	// **** END USER'S FUZZING LOGIC CALL ****

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
