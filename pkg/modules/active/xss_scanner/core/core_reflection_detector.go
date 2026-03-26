package core

import (
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// HTTPReflectionPointDetector implements the Crp interface.
// Original Java class: b5k
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

// NewHTTPReflectionPointDetector creates a new B5k instance and performs initial reflection scan.
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
// logic from erw.java that uses hqr.
func (detector *HTTPReflectionPointDetector) scanBytesForReflections(
	dataToScan []byte,
	payloadMatcher ByteSequenceMatcher, // This is the *E8u instance
	region *ByteScanRegion,
	location ReflectionLocation,
	sourceBodyOffset int, // hkk.g equivalent
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


	// Use newHqrInternal which accepts a Db9 interface directly
	// and also the originalPayloadForDc3
	payloadLocator := NewPayloadReflectionLocatorWithMatcher(
		dataToScan,        // var1: bytes being scanned
		sourceBodyOffset,  // var2: hkk.g, global body offset
		payloadMatcher,    // var3Db9: the e8u pattern (created from originalPayloadForHqr within NewHqr)
		region.StartIndex, // var4: offset in targetBytes
		region.EndIndex,   // var5: end in targetBytes
		location,          // var6: context for reflection
		randomProvider,    // var7NetOu
	)

	if payloadLocator != nil {
		// The Hqr.A method will call Crp.AEqxByte (which is b.AEqxByte)
		// to add discovered reflections. The canary for those Eqx objects
		// will be derived from b.payloadUsedInErwLogic by dc3 logic,
		// as dc3's constructor (called by hqr) takes this payload as its canary.
		payloadLocator.LocateReflections(detector)
	}
}

// AddReflection corresponds to Java: public void a(eqx var1, byte var2)
func (detector *HTTPReflectionPointDetector) AddReflection(
	reflection ReflectionOccurrenceDetail,
	location ReflectionLocation,
) {
	// Ensure eqxVal and its HPO are not nil before accessing fields
	if reflection == nil || reflection.CoreInfo() == nil {
		// Optionally log this situation
		return
	}
	pointInfo := reflection.CoreInfo()
	if pointInfo == nil { // Double check, though eqxVal.A() returning nil Hpo should be caught above
		return
	}
	switch location {
	case ReflectionLocationHeader: // Header context reflections
		detector.headerReflections = append(detector.headerReflections, reflection)
		contextFlagIndex := pointInfo.GetContextCode() // HPO.e is ReflectionType in Java HPO
		if contextFlagIndex < byte(len(detector.headerReflectionContextFlags)) {
			detector.headerReflectionContextFlags[contextFlagIndex] = true
		}

	case ReflectionLocationBody: // Body context reflections
		detector.bodyReflections = append(detector.bodyReflections, reflection)
		index := pointInfo.GetContextCode() // HPO.e is ReflectionType in Java HPO
		if index < byte(len(detector.bodyReflectionContextFlags)) {
			detector.bodyReflectionContextFlags[index] = true
		}
	default:
		// In Java, this case calls an assertion/error.
		// We can log or ignore for now.
	}
}

// HasReflectionContextFlag corresponds to Java: public boolean a(byte var1, byte var2)
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

// GetReflections corresponds to Java: public List<eqx> b(byte var1)
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

		if contentBytes[startIndex] > 32 {
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

// IsReflectionDataProvider marker method for Crp interface.
func (detector *HTTPReflectionPointDetector) IsReflectionDataProvider() {}

func (detector *HTTPReflectionPointDetector) GetTransaction() *utils.HTTPTransaction {
	return detector.transaction
}

// ByteScanRegion corresponds to the Java class burp.by9.
type ByteScanRegion struct {
	StartIndex int // Corresponds to public final int b; (start index or relevant int value)
	EndIndex   int // Corresponds to public final int a; (end index or relevant int value)
}

// NewByteScanRegion creates a new By9 instance.
func NewByteScanRegion(startIndex int, endIndex int) *ByteScanRegion {
	return &ByteScanRegion{
		StartIndex: startIndex,
		EndIndex:   endIndex,
	}
}

// HTTPResponseScanRegions corresponds to the Java class burp.bhy.
type HTTPResponseScanRegions struct {
	BodyRegion   *ByteScanRegion // For body scan region in Erw
	HeaderRegion *ByteScanRegion // For header scan region in Erw
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
