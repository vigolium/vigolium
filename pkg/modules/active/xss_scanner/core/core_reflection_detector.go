package core

import (
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// HTTPReflectionPointDetector detects payload reflections in HTTP responses.
type HTTPReflectionPointDetector struct {
	transaction           *utils.HTTPTransaction // Stores the full transaction
	payloadMatcherForScan ByteSequenceMatcher

	bodyReflections              []ReflectionOccurrenceDetail
	bodyReflectionContextFlags   []bool
	prioritizeHeaderReflections  bool
	headerReflections            []ReflectionOccurrenceDetail
	headerReflectionContextFlags []bool
	contentTypeProfile           *ContentTypeProfile

	scanTriggerPayload []byte
}

// NewHTTPReflectionPointDetector creates a new detector instance and performs initial reflection scan.
func NewHTTPReflectionPointDetector(
	transaction *utils.HTTPTransaction, // Changed to accept HTTPTransaction
	payloadMatcher ByteSequenceMatcher,
	triggerPayload []byte,
	randomProvider *utils.RandomGenerator,
) *HTTPReflectionPointDetector {
	if transaction == nil || !transaction.IsHasResponse() ||
		payloadMatcher == nil { // Guard against nil response
		return nil // Or handle error appropriately
	}

	detector := &HTTPReflectionPointDetector{
		transaction:           transaction,
		payloadMatcherForScan: payloadMatcher,
		scanTriggerPayload:    triggerPayload,

		bodyReflections:              make([]ReflectionOccurrenceDetail, 0),
		bodyReflectionContextFlags:   make([]bool, 26),
		headerReflections:            make([]ReflectionOccurrenceDetail, 0),
		headerReflectionContextFlags: make([]bool, 26),
	}

	detector.contentTypeProfile = NewContentTypeProfile(
		transaction.GetResponseHeaders(),
		transaction.GetResponseBody(),
	)

	detector.findReflections(payloadMatcher, randomProvider)

	return detector
}

func (detector *HTTPReflectionPointDetector) findReflections(
	payloadMatcher ByteSequenceMatcher,
	randomProvider *utils.RandomGenerator,
) {
	rawResponseHeaders := detector.transaction.GetRawResponseHeaders()
	detector.prioritizeHeaderReflections = (rawResponseHeaders != nil)

	scanRegions := detector.determineScanRegions(
		rawResponseHeaders,
		detector.transaction.GetResponseBody(),
	)

	if rawResponseHeaders != nil && scanRegions.HeaderRegion != nil {
		detector.scanBytesForReflections(
			rawResponseHeaders,
			payloadMatcher,
			scanRegions.HeaderRegion,
			ReflectionLocationHeader,
			len(detector.transaction.GetRawResponseHeaders()),
			randomProvider,
		)
	}

	if detector.transaction.IsHasResponse() && scanRegions.BodyRegion != nil {
		detector.scanBytesForReflections(
			detector.transaction.GetResponseBody(),
			payloadMatcher,
			scanRegions.BodyRegion,
			ReflectionLocationBody,
			len(detector.transaction.GetResponseBody()),
			randomProvider,
		)
	}
}

func (detector *HTTPReflectionPointDetector) determineScanRegions(
	headersBytes []byte,
	responseBody []byte,
) *HTTPResponseScanRegions {
	// bodyOffset := 0
	// bodyLength := 0
	// if responseBody != nil {
	// 	bodyLength = len(responseBody)
	// }

	// headerOffset := 0
	// headerLength := 0
	// if headersBytes != nil {
	// 	headerLength = len(headersBytes)
	// }

	bodyRegion := NewByteScanRegion(0, len(responseBody))
	headerRegion := NewByteScanRegion(0, len(headersBytes))

	return NewHTTPResponseScanRegions(bodyRegion, headerRegion)
}

// scanBytesForReflections attempts to replicate the reflection finding
func (detector *HTTPReflectionPointDetector) scanBytesForReflections(
	dataToScan []byte,
	payloadMatcher ByteSequenceMatcher,
	region *ByteScanRegion,
	location ReflectionLocation,
	sourceBodyOffset int,
	randomProvider *utils.RandomGenerator,
) {
	if dataToScan == nil || region == nil || payloadMatcher == nil ||
		region.StartIndex > region.EndIndex {
		return
	}
	firstMatch := payloadMatcher.FindMatch(dataToScan, region.StartIndex, region.EndIndex)
	if firstMatch == nil {
		return
	}

	payloadLocator := NewPayloadReflectionLocatorWithMatcher(
		dataToScan,
		sourceBodyOffset,
		payloadMatcher,
		region.StartIndex,
		region.EndIndex,
		location,
		randomProvider,
	)

	if payloadLocator != nil {
		payloadLocator.LocateReflections(detector)
	}
}

func (detector *HTTPReflectionPointDetector) AddReflection(
	reflection ReflectionOccurrenceDetail,
	location ReflectionLocation,
) {
	// Ensure reflection detail and its core info are not nil before accessing fields
	if reflection == nil || reflection.CoreInfo() == nil {
		// Optionally log this situation
		return
	}
	pointInfo := reflection.CoreInfo()
	if pointInfo == nil { // Double check, though reflection having nil core info should be caught above
		return
	}
	switch location {
	case ReflectionLocationHeader: // Header context reflections
		detector.headerReflections = append(detector.headerReflections, reflection)
		contextFlagIndex := pointInfo.GetContextCode()
		if contextFlagIndex < byte(len(detector.headerReflectionContextFlags)) {
			detector.headerReflectionContextFlags[contextFlagIndex] = true
		}

	case ReflectionLocationBody: // Body context reflections
		detector.bodyReflections = append(detector.bodyReflections, reflection)
		index := pointInfo.GetContextCode()
		if index < byte(len(detector.bodyReflectionContextFlags)) {
			detector.bodyReflectionContextFlags[index] = true
		}
	default:
		// We can log or ignore for now.
	}
}

func (detector *HTTPReflectionPointDetector) HasReflectionContextFlag(
	location ReflectionLocation,
	contextCode byte,
) bool {
	switch location {
	case ReflectionLocationHeader:
		if contextCode < byte(len(detector.headerReflectionContextFlags)) &&
			contextCode < byte(len(detector.bodyReflectionContextFlags)) {
			if detector.prioritizeHeaderReflections {
				return detector.headerReflectionContextFlags[contextCode]
			}
			return detector.bodyReflectionContextFlags[contextCode]
		}
		return false
	case ReflectionLocationBody:
		if contextCode < byte(len(detector.bodyReflectionContextFlags)) {
			return detector.bodyReflectionContextFlags[contextCode]
		}
		return false
	default:
		return false
	}
}

func (detector *HTTPReflectionPointDetector) GetReflections(
	location ReflectionLocation,
) []ReflectionOccurrenceDetail {
	if detector.transaction == nil || !detector.transaction.IsHasResponse() {
		return nil
	}
	switch location {
	case ReflectionLocationHeader:
		if detector.prioritizeHeaderReflections {
			return detector.headerReflections
		}
		return detector.bodyReflections
	case ReflectionLocationBody:
		return detector.bodyReflections
	default:
		return detector.bodyReflections
	}
}

func (detector *HTTPReflectionPointDetector) GetContentBytes(
	reflectionLocation ReflectionLocation,
) []byte {
	if detector.transaction == nil { // Guard against nil transaction
		return nil
	}
	switch reflectionLocation {
	case ReflectionLocationHeader:
		return detector.transaction.GetRawResponseHeaders()
	case ReflectionLocationBody:
		return detector.transaction.GetResponseBody()
	default:
		return detector.transaction.GetResponseBody()
	}
}

func (detector *HTTPReflectionPointDetector) GetResponseStatusCode(
	reflectionLocation ReflectionLocation,
) int {
	if detector.transaction == nil || !detector.transaction.IsHasResponse() {
		return 0 // Default or error indicator
	}
	return detector.transaction.GetResponseStatusCode()

}

func (detector *HTTPReflectionPointDetector) HasResponseWithHeaders() bool {
	return detector.transaction != nil && detector.transaction.IsHasResponse() &&
		len(detector.transaction.GetResponseHeaders()) > 0
}

func (detector *HTTPReflectionPointDetector) FindMatchingReflection(
	location ReflectionLocation,
	matcher ReflectionMatchCriterion,
) ReflectionOccurrenceDetail {
	reflectionsToCheck := detector.GetReflections(location)
	for _, reflectionLocation := range reflectionsToCheck {
		if reflectionLocation == nil || reflectionLocation.CoreInfo() == nil {
			continue
		}

		isMatch := false
		if matcher != nil {
			isMatch = matcher.Matches(reflectionLocation)
		}
		if isMatch {
			return reflectionLocation
		}
	}
	return nil
}

func (detector *HTTPReflectionPointDetector) IsReflectionRegionWhitespaceOrControl(
	reflection ReflectionOccurrenceDetail,
) bool {
	contentBytes := detector.GetContentBytes(ReflectionLocationBody)

	pointInfo := reflection.CoreInfo()
	startIndex := pointInfo.GetStartIndex()
	endIndex := pointInfo.GetEndIndex()
	for startIndex < endIndex {
		if startIndex < 0 || startIndex >= len(contentBytes) {
			return true
		}

		if contentBytes[startIndex] > charSpace {
			return false
		}
		startIndex++
	}
	return true
}

func (detector *HTTPReflectionPointDetector) HasBodyReflections() bool {
	list := detector.GetReflections(ReflectionLocationBody)
	return len(list) > 0
}

func (detector *HTTPReflectionPointDetector) HasHeaderReflections() bool {
	list := detector.GetReflections(ReflectionLocationHeader)
	return len(list) > 0
}

func (detector *HTTPReflectionPointDetector) HasAnyReflections() bool {
	return detector.HasHeaderReflections() || detector.HasBodyReflections()
}

func (detector *HTTPReflectionPointDetector) GetTriggerPayload() []byte {
	return detector.scanTriggerPayload
}

func (detector *HTTPReflectionPointDetector) GetContentTypeProfile() *ContentTypeProfile {
	if detector.contentTypeProfile == nil &&
		detector.transaction != nil &&
		detector.transaction.IsHasResponse() {
		detector.contentTypeProfile = NewContentTypeProfile(
			detector.transaction.GetResponseHeaders(),
			detector.transaction.GetResponseBody(),
		)
	}
	return detector.contentTypeProfile
}

func (detector *HTTPReflectionPointDetector) SetContentTypeProfile(profile *ContentTypeProfile) {
	detector.contentTypeProfile = profile
}

// IsReflectionDataProvider marker method for the reflection data provider interface.
func (detector *HTTPReflectionPointDetector) IsReflectionDataProvider() {}

func (detector *HTTPReflectionPointDetector) GetTransaction() *utils.HTTPTransaction {
	return detector.transaction
}

type ByteScanRegion struct {
	StartIndex int
	EndIndex   int
}

// NewByteScanRegion creates a new ByteScanRegion instance.
func NewByteScanRegion(startIndex int, endIndex int) *ByteScanRegion {
	return &ByteScanRegion{
		StartIndex: startIndex,
		EndIndex:   endIndex,
	}
}

type HTTPResponseScanRegions struct {
	BodyRegion   *ByteScanRegion
	HeaderRegion *ByteScanRegion
}

func NewHTTPResponseScanRegions(
	bodyRegion *ByteScanRegion,
	headerRegion *ByteScanRegion,
) *HTTPResponseScanRegions {
	return &HTTPResponseScanRegions{
		BodyRegion:   bodyRegion,
		HeaderRegion: headerRegion,
	}
}
