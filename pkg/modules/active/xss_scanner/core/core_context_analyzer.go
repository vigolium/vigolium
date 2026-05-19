package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

type ReflectionDetailVisitor interface {
	IsReflectionDetailVisitor()
	VisitHTTPHeaderReflection(httpHeaderReflection *HTTPHeaderReflection) interface{}
	VisitHTMLAttributeReflection(htmlAttributeReflection *HTMLAttributeReflection) interface{}
	VisitJavaScriptContextReflection(javaScriptContextReflection *JavaScriptContextReflection) interface{}
}

// It performs context analysis on a given segment of data.
type ReflectionContextualAnalyzer struct {
	reflectionDetector    *HTTPReflectionPointDetector
	startReflectionOffset int                        // start offset of reflection in body
	startBodyOffset       int                        // body offset (not an end offset)
	reflectionLocation    ReflectionLocation         // b
	randomProvider        *utils.RandomGenerator     // f
	initialMatchedBytes   []byte                     // c
	analysisResult        ReflectionOccurrenceDetail // a
}

// NewReflectionContextualAnalyzer creates a new ReflectionContextualAnalyzer instance.
func NewReflectionContextualAnalyzer(
	detector *HTTPReflectionPointDetector,
	reflectionStartOffset int,
	sourceBodyStartOffset int,
	reflectionLocation ReflectionLocation,
	randomProvider *utils.RandomGenerator,
	initialMatchedBytes []byte,
) *ReflectionContextualAnalyzer {
	contextualAnalyzer := &ReflectionContextualAnalyzer{
		reflectionDetector:    detector,
		startReflectionOffset: reflectionStartOffset,
		startBodyOffset:       sourceBodyStartOffset,
		reflectionLocation:    reflectionLocation,
		randomProvider:        randomProvider,
		initialMatchedBytes:   initialMatchedBytes,
	}
	contextualAnalyzer.analysisResult = contextualAnalyzer.performInternalAnalysis()
	return contextualAnalyzer
}

// AnalyzedReflection returns the result of the analysis.
func (analyzer *ReflectionContextualAnalyzer) AnalyzedReflection() ReflectionOccurrenceDetail {
	return analyzer.analysisResult
}

// performInternalAnalysis performs the main context analysis.
func (analyzer *ReflectionContextualAnalyzer) performInternalAnalysis() ReflectionOccurrenceDetail {
	contentBytes := analyzer.reflectionDetector.GetContentBytes(
		analyzer.reflectionLocation,
	)
	if analyzer.reflectionLocation == ReflectionLocationHeader {
		return analyzer.analyzeHTTPHeaderValue(contentBytes)
	}

	isScriptContext := false
	isPathEndingWithHTML := false

	contentTypeProfile := analyzer.reflectionDetector.GetContentTypeProfile()
	contentTypeHeaderValue := strings.ToLower(contentTypeProfile.GetContentTypeHeaderValue())
	if contentTypeProfile != nil {
		statedContentTypeCode := contentTypeProfile.GetStatedTypeCode()
		isScriptContext = statedContentTypeCode == DefTypeScript
		if analyzer.reflectionDetector.GetTransaction() != nil &&
			analyzer.reflectionDetector.GetTransaction().GetRequest() != nil &&
			analyzer.reflectionDetector.GetTransaction().GetRequest().URL != nil {
			isPathEndingWithHTML = strings.HasSuffix(
				strings.ToLower(
					analyzer.reflectionDetector.GetTransaction().
						GetRequest().
						URL.EscapedPath(),
				),
				".html",
			) || statedContentTypeCode == DefTypeHTML
		}

		isJsonOverride := strings.Contains(contentTypeHeaderValue, "json")
		isImageOverride := strings.HasPrefix(contentTypeHeaderValue, "image/")

		if isJsonOverride || isImageOverride {
			isPathEndingWithHTML = false
		}

	} else {
		zap.L().Debug("Error: contentTypeProfile is nil for context check in contextAnalyzer.performInternalAnalysis")
	}
	zap.L().Debug("context analysis",
		zap.Bool("isScriptContext", isScriptContext),
		zap.Bool("isPathEndingWithHTML", isPathEndingWithHTML))

	if isScriptContext || isPathEndingWithHTML {
		htmlScriptAnalyzer := NewHTMLScriptReflectionAnalyzer(
			analyzer.startReflectionOffset,
			0,
			analyzer.initialMatchedBytes,
		)
		zap.L().Debug("htmlScriptAnalyzer created", zap.Any("analyzer", htmlScriptAnalyzer))
		// Assuming A(10) is the simplified equivalent for now if B() methods are not defined or lead to issues.
		randomCanarySuffix := analyzer.randomProvider.GeneratePrefixedAlphanumeric(10)
		randomCanaryBytes := utils.StringToBytes(randomCanarySuffix)

		patchedContentData := analyzer.patchDataWithCanary(contentBytes, randomCanaryBytes)
		// zap.L().Debug("patchedSourceData", zap.String("data", string(patchedSourceData)))
		zap.L().Debug("patchedSourceData",
			zap.Int("patchedLen", len(patchedContentData)),
			zap.Int("sourceBytesLen", len(contentBytes)))

		if isScriptContext {
			return htmlScriptAnalyzer.AnalyzeJavaScriptContent(
				analyzer.reflectionLocation,
				patchedContentData,
				randomCanaryBytes,
				0,
				len(patchedContentData),
			)
		}
		analysisResult, err := htmlScriptAnalyzer.AnalyzeHTMLContext(
			analyzer.reflectionLocation,
			patchedContentData,
			randomCanaryBytes,
		)
		if err != nil {
			zap.L().Error("Error in htmlScriptAnalyzer.AnalyzeHTMLContext", zap.Error(err))
		}

		if analysisResult != nil {
			return analysisResult
		}

	}

	return NewReflectionPointCoreInfo(
		analyzer.reflectionLocation,
		ReflectionContextXMLGeneric,
		analyzer.startReflectionOffset,
		analyzer.startBodyOffset,
		analyzer.initialMatchedBytes,
	)
}

// analyzeHTTPHeaderValue analyzes data assuming it's a simple header line.
func (analyzer *ReflectionContextualAnalyzer) analyzeHTTPHeaderValue(
	headerBytes []byte,
) ReflectionOccurrenceDetail {

	var parsedHeaderName, parsedHeaderValue string

	// The end offset defaults to startReflectionOffset if no LF is found initially,
	// and is updated as header parsing progresses.

	reflectionPointEndOffset := analyzer.startReflectionOffset

	// Search for LF up to the injection point.
	lineFeedIndex := utils.LastIndexOfByteCS(
		headerBytes,
		charLineFeed,
		0,
		analyzer.startReflectionOffset,
	)

	searchStartIndex := 0

	if lineFeedIndex != -1 {
		searchStartIndex = lineFeedIndex + 1
		reflectionPointEndOffset = searchStartIndex
		// Corrected logic for colon search start:
		colonIndex := utils.IndexOfByteCS(
			headerBytes,
			':',
			searchStartIndex,               // Search for colon starts right after the initial LF's position.
			analyzer.startReflectionOffset, // Search up to the original injection point.
		)

		if colonIndex != -1 {
			headerNameEndIndex := colonIndex

			// Ensure currentSearchPos is not past nameSliceEnd for a valid slice.
			if searchStartIndex < headerNameEndIndex { // Check to prevent empty or invalid slice
				headerNameBytes := headerBytes[searchStartIndex:headerNameEndIndex]
				parsedHeaderName = strings.TrimSpace(
					utils.BytesToString(headerNameBytes),
				)
			} else if searchStartIndex == headerNameEndIndex { // Name is empty string if colon is right after LF+spaces
				parsedHeaderName = ""
			}

			searchStartIndex = colonIndex + 1 // Move past the colon
			_ = reflectionPointEndOffset      // Used for tracking, value updated later if needed

			// Skip leading spaces in header value.
			for searchStartIndex < analyzer.startBodyOffset && searchStartIndex < len(headerBytes) && headerBytes[searchStartIndex] == ' ' {
				searchStartIndex++
			}
			// If spaces were skipped, currentSearchPos advanced.
			// hpoReflectionEndPos should be the start of the value (after spaces).
			reflectionPointEndOffset = searchStartIndex

			// Find next LF for value.
			// Search from currentSearchPos (after colon and spaces) up to d.endOffset.
			nextLinkFeedIndex := utils.IndexOfByteCS(
				headerBytes,
				charLineFeed,
				searchStartIndex,         // from
				analyzer.startBodyOffset, // to
			)

			headerValueStartIndex := searchStartIndex
			var headerValueEndIndex int

			if nextLinkFeedIndex != -1 {
				headerValueEndIndex = nextLinkFeedIndex
			} else {
				// If no final LF, value extends to d.endOffset or end of headerBytes if shorter.
				headerValueEndIndex = analyzer.startBodyOffset
			}

			// Ensure valueSliceEnd does not exceed headerBytes actual length
			if headerValueEndIndex > len(headerBytes) {
				headerValueEndIndex = len(headerBytes)
			}

			// Only slice if start is before end and within bounds of headerBytes
			if headerValueStartIndex < headerValueEndIndex &&
				headerValueStartIndex < len(headerBytes) {
				headerValueBytes := headerBytes[headerValueStartIndex:headerValueEndIndex]
				parsedHeaderValue = strings.TrimSpace(
					utils.BytesToString(headerValueBytes),
				)
			} else if headerValueStartIndex == headerValueEndIndex || headerValueStartIndex >= len(headerBytes) {
				// Value is empty if start is at or past end, or out of bounds
				parsedHeaderValue = ""
			}

		} // else (no colon): headerName and headerValue remain empty. hpoReflectionEndPos is currentSearchPos (after initial LF).
	} // else (no initial LF): headerName, headerValue remain empty. hpoReflectionEndPos is d.startOffset.

	return NewHTTPHeaderReflection(
		NewReflectionPointCoreInfo(
			analyzer.reflectionLocation,
			1,
			analyzer.startReflectionOffset,
			reflectionPointEndOffset,
			analyzer.initialMatchedBytes,
		),
		parsedHeaderName,
		parsedHeaderValue,
	)
}

// patchDataWithCanary creates a new byte slice with a canary replacement.
func (analyzer *ReflectionContextualAnalyzer) patchDataWithCanary(
	sourceData []byte,
	replacementCanary []byte,
) []byte {
	if sourceData == nil {
		zap.L().Warn("originalData is nil in constructPatchedDataInternal, returning canaryReplacement directly")
		// If canaryReplacement is also nil, CombineByteSlices should handle it.
		return utils.CombineByteSlices(
			nil,
			replacementCanary,
			nil,
		) // Match structure of combine
	}

	// part1: prefix bytes from start of source to start of reflection

	prefixBytes := []byte{}
	// Extract bytes from start of source to start of reflection
	if analyzer.startReflectionOffset > 0 && analyzer.startReflectionOffset <= len(sourceData) {
		prefixBytes = utils.CopyOfRange(
			sourceData,
			0,
			analyzer.startReflectionOffset,
		)
	}

	// part3: suffix bytes from end of matched region to end of source
	suffixStartIndex := analyzer.startReflectionOffset + len(analyzer.initialMatchedBytes)
	suffixBytes := []byte{}
	if suffixStartIndex < len(sourceData) {
		suffixBytes = utils.CopyOfRange(
			sourceData,
			suffixStartIndex,
			len(sourceData),
		)
	}

	// Ensure canaryReplacement is not nil if it's passed to CombineByteSlices
	finalReplacementCanary := replacementCanary
	if finalReplacementCanary == nil {
		finalReplacementCanary = []byte{}
	}

	// Combine: prefix + canary + suffix
	patchedData := utils.CombineByteSlices(prefixBytes, finalReplacementCanary, suffixBytes)

	zap.L().Debug("constructPatchedDataInternal",
		zap.Int("originalLen", len(sourceData)),
		zap.Int("startOffset", analyzer.startReflectionOffset),
		zap.Int("endOffset", analyzer.startBodyOffset),
		zap.Int("matchedLen", len(analyzer.initialMatchedBytes)))
	zap.L().Debug("patched data parts",
		zap.Int("part1Len", len(prefixBytes)),
		zap.Int("canaryLen", len(finalReplacementCanary)),
		zap.Int("part3Len", len(suffixBytes)),
		zap.Int("resultLen", len(patchedData)))

	return patchedData
}
