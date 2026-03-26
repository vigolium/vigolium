package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

type ReflectionDetailVisitor interface {
	IsEnaVisitor()
	VisitE1t(httpHeaderReflection *HTTPHeaderReflection) interface{}
	VisitFcp(htmlAttributeReflection *HTMLAttributeReflection) interface{}
	VisitFcg(javaScriptContextReflection *JavaScriptContextReflection) interface{}
}

// ReflectionContextualAnalyzer corresponds to the Java class dc3.
// It performs context analysis on a given segment of data.
type ReflectionContextualAnalyzer struct {
	reflectionDetector    *HTTPReflectionPointDetector
	startReflectionOffset int                        // d - start offset của reflection trong body
	startBodyOffset       int                        // g - KHÔNG PHẢI end offset! Đây là bodyOffset từ hqr
	reflectionLocation    ReflectionLocation         // b
	randomProvider        *utils.RandomGenerator     // f
	initialMatchedBytes   []byte                     // c
	analysisResult        ReflectionOccurrenceDetail // a
}

// NewReflectionContextualAnalyzer creates a new Dc3 instance.
// Corresponds to Java constructor: dc3(crp var1, int var2, int var3, byte var4, ou var5, byte[] var6)
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
// Corresponds to Java public eqx b()
func (analyzer *ReflectionContextualAnalyzer) AnalyzedReflection() ReflectionOccurrenceDetail {
	return analyzer.analysisResult
}

// performInternalAnalysis performs the main context analysis.
// Corresponds to private eqx a() in Java.
func (analyzer *ReflectionContextualAnalyzer) performInternalAnalysis() ReflectionOccurrenceDetail {
	contentBytes := analyzer.reflectionDetector.GetContentBytes(
		analyzer.reflectionLocation,
	) // this.e.a(this.b)
	if analyzer.reflectionLocation == ReflectionLocationHeader {
		return analyzer.analyzeHTTPHeaderValue(contentBytes)
	}

	// Content type determination using def.java logic
	isScriptContext := false
	isPathEndingWithHTML := false // Corresponds to Java's boolean var4 (a4e.b(...))

	contentTypeProfile := analyzer.reflectionDetector.GetContentTypeProfile() // Corresponds to this.e.c()
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
			isPathEndingWithHTML = false // Nếu là JSON (với cờ F) hoặc Image, var4 = false
		}

	} else {
		zap.L().Debug("Error: crpInstance.CDef() is nil for context check in dc3.analyzeInternal")
	}
	zap.L().Debug("context analysis",
		zap.Bool("isScriptContext", isScriptContext),
		zap.Bool("isPathEndingWithHTML", isPathEndingWithHTML))

	if isScriptContext || isPathEndingWithHTML {
		htmlScriptAnalyzer := NewHTMLScriptReflectionAnalyzer(
			analyzer.startReflectionOffset,
			0,
			analyzer.initialMatchedBytes,
		) // new bca(this.d, this.g, this.c)
		zap.L().Debug("bcaAnalyzer created", zap.Any("analyzer", htmlScriptAnalyzer))
		// Original Java: String var6 = this.f.b().b().a(10);
		// Assuming A(10) is the simplified equivalent for now if B() methods are not defined or lead to issues.
		randomCanarySuffix := analyzer.randomProvider.GeneratePrefixedAlphanumeric(10)
		randomCanaryBytes := utils.StringToBytes(randomCanarySuffix)

		// Java: var8 = this.a(var2, var7); (var2 is sourceBytes, var7 is canaryStringAsBytes)
		patchedContentData := analyzer.patchDataWithCanary(contentBytes, randomCanaryBytes)
		// zap.L().Debug("patchedSourceData", zap.String("data", string(patchedSourceData)))
		zap.L().Debug("patchedSourceData",
			zap.Int("patchedLen", len(patchedContentData)),
			zap.Int("sourceBytesLen", len(contentBytes)))

		if isScriptContext {
			// Java: return var5.a(this.b, var8, var7, 0, var8.length); (var5 is bcaAnalyzer)
			// The return in Java is conditional later. Here we assign to eqxResult.
			return htmlScriptAnalyzer.AnalyzeJavaScriptContent(
				analyzer.reflectionLocation, // this.b
				patchedContentData,          // var8
				randomCanaryBytes,           // var7
				0,                           // 0
				len(patchedContentData),     // var8.length
			)
		}
		// Java: eqx var9 = var17.a(var20.b, var8, var7); (var17 is bcaAnalyzer)
		analysisResult, err := htmlScriptAnalyzer.AnalyzeHTMLContext(
			analyzer.reflectionLocation, // var20.b (this.b)
			patchedContentData,          // var8
			randomCanaryBytes,           // var7
		)
		if err != nil {
			zap.L().Error("Error in bcaAnalyzer.AnalyzeGeneralContext", zap.Error(err))
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
// Corresponds to private eqx a(byte[] var1) in Java.
func (analyzer *ReflectionContextualAnalyzer) analyzeHTTPHeaderValue(
	headerBytes []byte,
) ReflectionOccurrenceDetail { // var1 is headerBytes

	var parsedHeaderName, parsedHeaderValue string // var3, var4 in Java

	// Java's corresponding method (the second private eqx a(byte[] var1)) initializes
	// a variable `var2` from `hpo.c()` (which returns a non-zero value).
	// This `var2` is then used in a `while` loop's conditional break: `if (var2 == 0) break;`.
	// Since `var2` is non-zero, the condition `var2 == 0` is always false.
	// Consequently, the `break` statement is effectively dead code.
	// This Go implementation correctly omits this dead break and does not need to call HpoStaticC()
	// as its specific value isn't used, only its non-zero property (which is known).

	// In Java, var5 is the critical offset that becomes the HPO's end position.
	// It's initialized to this.d (d.startOffset) if no LF is found initially.
	// If LF found, var5 becomes LF_index + 1.
	// If colon found, var5 becomes colon_index + 1.
	// After skipping spaces, var5 is updated again. This final var5 is used in `new hpo(..., this.d, var5, ...)`
	// So, the HPO's `endOffset` (the 4th param to HPO constructor) is effectively `currentSearchPos` at the point the value parsing begins.

	reflectionPointEndOffset := analyzer.startReflectionOffset // This will track Java's `var5` that goes into HPO constructor

	// Search for LF up to the injection point.
	lineFeedIndex := utils.LastIndexOfByteCS(
		headerBytes,
		10,
		0,
		analyzer.startReflectionOffset,
	)

	searchStartIndex := 0 // Placeholder, will be updated like Java's var5

	if lineFeedIndex != -1 {
		searchStartIndex = lineFeedIndex + 1
		reflectionPointEndOffset = searchStartIndex // Java's var5 is updated
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

			// Skip spaces after colon. Java: while (var5 < this.g && var1[var5] == 32)
			// this.g is d.endOffset. Loop until d.endOffset or non-space.
			for searchStartIndex < analyzer.startBodyOffset && searchStartIndex < len(headerBytes) && headerBytes[searchStartIndex] == ' ' {
				searchStartIndex++
				// The dead break `if (hpo.c_value == 0) { break; }` from the original Java
				// (where hpo.c_value comes from hpo.c()) is intentionally omitted here.
				// This is because hpo.c() returns a non-zero value, making the break condition
				// always false, as per the java_obfuscation_static_controlled_loop.mdc pattern.
			}
			// If spaces were skipped, currentSearchPos advanced.
			// hpoReflectionEndPos should be the start of the value (after spaces).
			reflectionPointEndOffset = searchStartIndex

			// Find next LF for value.
			// Search from currentSearchPos (after colon and spaces) up to d.endOffset.
			nextLinkFeedIndex := utils.IndexOfByteCS(
				headerBytes,
				10,                       // LF
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
// Corresponds to private byte[] a(byte[] var1, byte[] var2) in Java.
// var1 is originalData, var2 is canaryReplacement.
func (analyzer *ReflectionContextualAnalyzer) patchDataWithCanary(
	sourceData []byte,
	replacementCanary []byte,
) []byte {
	if sourceData == nil {
		zap.L().Warn("originalData is nil in constructPatchedDataInternal, returning canaryReplacement directly")
		// Java might throw NPE. Returning canary if original is nil is a possible interpretation if nk.a handles it or fails.
		// If canaryReplacement is also nil, CombineByteSlices should handle it.
		return utils.CombineByteSlices(
			nil,
			replacementCanary,
			nil,
		) // Match structure of combine
	}

	// part1: prefix bytes from start of source to start of reflection

	prefixBytes := []byte{}
	// Thử với logic: lấy từ đầu đến start của reflection
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
