package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

var htmlEventHandlers = []string{
	"onabort", "oncancel", "oncanplay", "oncanplaythrough", "onchange",
	"onclick", "onclose", "oncontextmenu", "oncuechange", "ondblclick",
	"ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover",
	"ondragstart", "ondrop", "ondurationchange", "onemptied", "onended",
	"oninput", "oninvalid", "onkeydown", "onkeypress", "onkeyup",
	"onloadeddata", "onloadedmetadata", "onloadstart", "onmousedown",
	"onmousemove", "onmouseout", "onmouseover", "onmouseup", "onmousewheel",
	"onpause", "onplay", "onplaying", "onprogress", "onratechange",
	"onreset", "onseeked", "onseeking", "onselect", "onshow",
	"onstalled", "onsubmit", "onsuspend", "ontimeupdate", "onvolumechange",
	"onwaiting", "onafterprint", "onanimationend", "onanimationiteration",
	"onanimationstart", "onaudioprocess", "onbeforeprint", "onbeforeunload",
	"onbeginEvent", "onblocked", "onblur", "oncached", "onchargingchange",
	"onchargingtimechange", "onchecking", "oncompassneedscalibration",
	"oncompositionend", "oncompositionstart", "oncompositionupdate", "oncopy",
	"oncut", "ondevicelight", "ondevicemotion", "ondeviceorientation",
	"ondeviceproximity", "ondischargingtimechange", "onDOMActivate",
	"onDOMAttributeNameChanged", "onDOMAttrModified", "onDOMCharacterDataModified",
	"onDOMContentLoaded", "onDOMElementNameChanged", "onDOMFocusIn",
	"onDOMFocusOut", "onDOMNodeInserted", "onDOMNodeInsertedIntoDocument",
	"onDOMNodeRemoved", "onDOMNodeRemovedFromDocument", "onDOMSubtreeModified",
	"ondownloading", "onendEvent", "onfocus", "onfocusin", "onfocusout",
	"onfullscreenchange", "onfullscreenerror", "ongamepadconnected",
	"ongamepaddisconnected", "onhashchange", "onlevelchange", "onloadend",
	"onmouseenter", "onmouseleave", "onnoupdate", "onobsolete", "onoffline",
	"ononline", "onorientationchange", "onpagehide", "onpageshow", "onpaste",
	"onpointerlockchange", "onpointerlockerror", "onpopstate",
	"onreadystatechange", "onrepeatEvent", "onresize", "onscroll",
	"onstorage", "onsuccess", "onSVGAbort", "onSVGError", "onSVGLoad",
	"onSVGResize", "onSVGScroll", "onSVGUnload", "onSVGZoom", "ontimeout",
	"ontouchcancel", "ontouchend", "ontouchenter", "ontouchleave",
	"ontouchmove", "ontouchstart", "ontransitionend", "onunload",
	"onupdateready", "onupgradeneeded", "onuserproximity", "onversionchange",
	"onvisibilitychange", "onwheel", "onactivate", "onbeforeactivate",
	"onerror", "onformchange", "onforminput", "onload", "onmessage",
	"onpropertychange", "onredo", "onundo",
}

type HTMLScriptReflectionAnalyzer struct {
	reflectionInsertionPoint int
	sourceBodyOffset         int
	searchCanaryBytes        []byte
	currentOpenTags          map[string]struct{}
}

// NewHTMLScriptReflectionAnalyzer creates a new HTMLScriptReflectionAnalyzer.
func NewHTMLScriptReflectionAnalyzer(
	reflectionInsertionPoint int,
	sourceBodyOffset int,
	searchCanaryBytes []byte,
) *HTMLScriptReflectionAnalyzer {
	zap.L().Debug("NewHTMLScriptReflectionAnalyzer",
		zap.Int("startIdx", reflectionInsertionPoint),
		zap.Int("endIdx", sourceBodyOffset),
		zap.String("canaryTokenBytes", string(searchCanaryBytes)))
	return &HTMLScriptReflectionAnalyzer{
		reflectionInsertionPoint: reflectionInsertionPoint,
		sourceBodyOffset:         sourceBodyOffset,
		searchCanaryBytes:        searchCanaryBytes,
		currentOpenTags:          make(map[string]struct{}),
	}
}

// It analyzes HTML-like content for reflections.
func (analyzer *HTMLScriptReflectionAnalyzer) AnalyzeHTMLContext(
	location ReflectionLocation,
	contentToAnalyze []byte,
	canaryToFind []byte,
) (ReflectionOccurrenceDetail, error) {
	zap.L().Debug("Entering AnalyzeGeneralContext",
		zap.Int("matchBytesRangeLen", len(contentToAnalyze)),
		zap.String("canaryToken", string(canaryToFind)))
	zap.L().Debug("HTMLScriptReflectionAnalyzer fields",
		zap.Int("startReflectionIdx", analyzer.reflectionInsertionPoint),
		zap.Int("startBodyOffsetInFullResponse", analyzer.sourceBodyOffset),
		zap.String("canaryTokenBytes", string(analyzer.searchCanaryBytes)))

	canaryStringTofind := utils.BytesToString(canaryToFind)

	parsedElements, err := htmlparser.ParseHTMLElements(
		contentToAnalyze,
		0,
		len(contentToAnalyze),
		0, //TODO: HTML and XML?
		htmlparser.ParseModeFull,
		nil,
	)
	if err != nil {
		return nil, err
	}

	for _, currentElement := range parsedElements {

		isInsertionPointInElement := analyzer.reflectionInsertionPoint >= (currentElement.StartOffset+analyzer.sourceBodyOffset) &&
			analyzer.reflectionInsertionPoint < (currentElement.EndOffset+analyzer.sourceBodyOffset)

		// Check if the element contains the canary token to determine reflection membership
		doesElementContainCanary := false
		if currentElement.Type == htmlparser.TextNode &&
			currentElement.EndOffset <= len(contentToAnalyze) &&
			currentElement.StartOffset < currentElement.EndOffset &&
			currentElement.StartOffset >= 0 {
			currentElementContent := string(
				contentToAnalyze[currentElement.StartOffset:currentElement.EndOffset],
			)
			if strings.Contains(currentElementContent, canaryStringTofind) {
				doesElementContainCanary = true
				zap.L().Debug("Found canary in TextNode",
					zap.Int("startOffset", currentElement.StartOffset),
					zap.Int("endOffset", currentElement.EndOffset))
			}
		}

		if doesElementContainCanary {
			isInsertionPointInElement = true
		}

		// log.Debugf(
		// 	"Checking element - StartOffset: %d, EndOffset: %d, Type: %d",
		// 	currentElement.StartOffset,
		// 	currentElement.EndOffset,
		// 	currentElement.Type,
		// )
		// log.Debugf(
		// 	"Range check: %d >= %d && %d < %d = %v",
		// 	analyzer.reflectionInsertionPoint,
		// 	currentElement.StartOffset+analyzer.sourceBodyOffset,
		// 	analyzer.reflectionInsertionPoint,
		// 	currentElement.EndOffset+analyzer.sourceBodyOffset,
		// 	isInsertionPointInElement,
		// )

		zap.L().Debug("htmlElement", zap.String("element", currentElement.String()))
		if currentElement.TagInfo != nil {
			zap.L().Debug("htmlElement.TagInfo", zap.String("tagInfo", currentElement.TagInfo.String()))
		}
		zap.L().Debug("reflection analysis",
			zap.Bool("isReflectionInElementRange", isInsertionPointInElement),
			zap.Bool("elementContainsCanary", doesElementContainCanary))

		switch currentElement.Type {
		case htmlparser.OpenTag,
			htmlparser.CloseTag,
			htmlparser.SelfClosingTagOrPI: // Cases 0, 1, 4
			if isInsertionPointInElement {
				if currentElement.TagInfo != nil {
					if strings.Contains(currentElement.TagInfo.Name, canaryStringTofind) {
						return NewReflectionPointCoreInfo(
							location,
							ReflectionContextHTMLTagCloseAndInject,
							analyzer.reflectionInsertionPoint,
							currentElement.StartOffset+analyzer.sourceBodyOffset,
							analyzer.searchCanaryBytes,
						), nil
					}

					for _, currentAttribute := range currentElement.TagInfo.Attributes {
						if strings.Contains(currentAttribute.Name, canaryStringTofind) {
							reflectionInfo := NewReflectionPointCoreInfo(
								location,
								ReflectionContextHTMLAttributeName,
								analyzer.reflectionInsertionPoint,
								currentAttribute.NameStart+analyzer.sourceBodyOffset,
								analyzer.searchCanaryBytes,
							)
							// Ensure TagInfo is passed correctly. If htmlElement.TagInfo is nil, this would panic. Handled by outer nil check.
							return NewHTMLAttributeReflection(
								reflectionInfo,
								currentElement.TagInfo.Name,
								"",
								"",
								currentElement.TagInfo,
							), nil
						}

						if strings.Contains(currentAttribute.Value, canaryStringTofind) {
							detectedReflection := analyzer.analyzeReflectionInHTMLAttribute(
								location,
								currentElement,
								currentAttribute,
								canaryStringTofind,
							)
							if detectedReflection != nil {
								return detectedReflection, nil
							}
						}
					}
				}
			}
			analyzer.updateCurrentOpenTags(currentElement)

		case htmlparser.CommentOrDirective: // Case 2
			if isInsertionPointInElement {
				return NewReflectionPointCoreInfo(
					location,
					ReflectionContextHTMLCommentBreakout,
					analyzer.reflectionInsertionPoint,
					currentElement.StartOffset+analyzer.sourceBodyOffset,
					analyzer.searchCanaryBytes,
				), nil
			}

		case htmlparser.TextNode: // Case 3
			if isInsertionPointInElement {
				return analyzer.analyzeTextNodeInSpecialTag(
					location,
					contentToAnalyze,
					canaryToFind,
					currentElement.StartOffset,
					currentElement.EndOffset,
				), nil
			}
		}
	}

	// Debug active tags before returning
	zap.L().Debug("Active tags at end of AnalyzeGeneralContext", zap.Any("activeTags", analyzer.currentOpenTags))

	return nil, nil
}

func (analyzer *HTMLScriptReflectionAnalyzer) analyzeReflectionInHTMLAttribute(
	location ReflectionLocation,
	element *htmlparser.HTMLElement,
	attr *htmlparser.HTMLAttribute,
	canary string,
) ReflectionOccurrenceDetail {
	isURLAttributeType := analyzer.isAttributeURLType(element, attr)
	isEventHandlerAttributeType := false

	if !isURLAttributeType {
		for _, knownEventHandlerName := range htmlEventHandlers { // String var11 : a
			if strings.EqualFold(
				knownEventHandlerName,
				attr.Name,
			) {
				isEventHandlerAttributeType = true
				break
			}
		}
	}

	attributeValueWithReplacedCanary := analyzer.replaceCanaryInAttributeValue(canary, attr)

	var determinedContextType ReflectionContext
	attrQuoteType := attr.QuoteType

	if isURLAttributeType {
		switch attrQuoteType {
		case htmlparser.QuoteTypeDouble:
			determinedContextType = ReflectionContextJSInURLAttributeDQ
		case htmlparser.QuoteTypeSingle:
			determinedContextType = ReflectionContextJSInURLAttributeSQ
		case htmlparser.QuoteTypeBacktick:
			determinedContextType = ReflectionContextJSInURLAttributeBT
		case htmlparser.QuoteTypeNone:
			determinedContextType = ReflectionContextJSInUnquotedURLAttribute
		default:
			return nil
		}
	} else if isEventHandlerAttributeType {
		switch attrQuoteType {
		case htmlparser.QuoteTypeDouble:
			determinedContextType = ReflectionContextJSInEventHandlerDQ
		case htmlparser.QuoteTypeSingle:
			determinedContextType = ReflectionContextJSInEventHandlerSQ
		case htmlparser.QuoteTypeBacktick:
			determinedContextType = ReflectionContextJSInEventHandlerBT
		case htmlparser.QuoteTypeNone:
			determinedContextType = ReflectionContextJSInHTMLTagGeneric
		default:
			return nil
		}
	} else { // Normal attribute
		switch attrQuoteType {
		case htmlparser.QuoteTypeDouble:
			determinedContextType = ReflectionContextHTMLAttributeValueDQBreakout
		case htmlparser.QuoteTypeSingle:
			determinedContextType = ReflectionContextHTMLAttributeValueSQBreakout
		case htmlparser.QuoteTypeBacktick:
			determinedContextType = ReflectionContextHTMLAttributeValueBTBreakout
		case htmlparser.QuoteTypeNone:
			determinedContextType = ReflectionContextHTMLAttributeValueUnquotedBreakout
		default:
			return nil
		}
	}

	reflectionInfo := NewReflectionPointCoreInfo(
		location,
		determinedContextType,
		analyzer.reflectionInsertionPoint,
		attr.ValueStart+analyzer.sourceBodyOffset,
		analyzer.searchCanaryBytes,
	)

	if element.TagInfo == nil {
		// This case should ideally not happen if attribute exists, but good for safety.
		return nil
	}
	return NewHTMLAttributeReflection(
		reflectionInfo,
		element.TagInfo.Name,
		attr.Name,
		attributeValueWithReplacedCanary,
		element.TagInfo,
	)
}

func (analyzer *HTMLScriptReflectionAnalyzer) isAttributeURLType(
	element *htmlparser.HTMLElement,
	attr *htmlparser.HTMLAttribute,
) bool {
	if element.TagInfo == nil {
		return false // Cannot determine if TagInfo is missing
	}
	currentTagName := element.TagInfo.Name
	currentAttributeName := attr.Name

	if (!strings.EqualFold("src", currentAttributeName) && !strings.EqualFold("data", currentAttributeName)) ||
		(!strings.EqualFold("iframe", currentTagName) && !strings.EqualFold("object", currentTagName) && !strings.EqualFold("embed", currentTagName) && !strings.EqualFold("frame", currentTagName)) {
		if !strings.EqualFold("href", currentAttributeName) ||
			(!strings.EqualFold("a", currentTagName) && !strings.EqualFold("math", currentTagName)) {
			if !strings.EqualFold("formaction", currentAttributeName) ||
				(!strings.EqualFold("button", currentTagName) && !strings.EqualFold("input", currentTagName)) {
				return strings.EqualFold("action", currentAttributeName) &&
					strings.EqualFold("form", currentTagName)
			}
			return true
		}
		return true
	}
	return true
}

func (analyzer *HTMLScriptReflectionAnalyzer) updateCurrentOpenTags(
	element *htmlparser.HTMLElement,
) {

	if element.TagInfo == nil {
		return
	}
	lowerCaseTagName := strings.ToLower(element.TagInfo.Name)

	if element.Type == htmlparser.CloseTag {
		delete(analyzer.currentOpenTags, lowerCaseTagName)
		// This means if it's a close tag, it removes and then returns.
		return
	}

	// This part is for OpenTag or SelfClosingTagOrPI (implicitly, as it's not CloseTag and didn't return)
	analyzer.currentOpenTags[lowerCaseTagName] = struct{}{}
}

func (analyzer *HTMLScriptReflectionAnalyzer) analyzeTextNodeInSpecialTag(
	location ReflectionLocation,
	fullContent []byte,
	canary []byte,
	nodeStartIndex int,
	nodeEndIndex int,
) ReflectionOccurrenceDetail {
	reflectionPointStartIndex := nodeStartIndex + analyzer.sourceBodyOffset

	if _, ok := analyzer.currentOpenTags["script"]; ok {
		return analyzer.AnalyzeJavaScriptContent(
			location,
			fullContent,
			canary,
			nodeStartIndex,
			nodeEndIndex,
		)
	}
	if _, ok := analyzer.currentOpenTags["xmp"]; ok {
		return NewReflectionPointCoreInfo(
			location,
			ReflectionContextHTMLAfterXMPClose,
			analyzer.reflectionInsertionPoint,
			reflectionPointStartIndex,
			analyzer.searchCanaryBytes,
		)
	}
	if _, ok := analyzer.currentOpenTags["noscript"]; ok {
		return NewReflectionPointCoreInfo(
			location,
			ReflectionContextHTMLAfterNoscriptClose,
			analyzer.reflectionInsertionPoint,
			reflectionPointStartIndex,
			analyzer.searchCanaryBytes,
		)
	}
	if _, ok := analyzer.currentOpenTags["title"]; ok {
		return NewReflectionPointCoreInfo(
			location,
			ReflectionContextHTMLAfterTitleClose,
			analyzer.reflectionInsertionPoint,
			reflectionPointStartIndex,
			analyzer.searchCanaryBytes,
		)
	}
	// Default for other text nodes if reflection is within them
	return NewReflectionPointCoreInfo(
		location,
		ReflectionContextXMLGeneric,
		analyzer.reflectionInsertionPoint,
		reflectionPointStartIndex,
		analyzer.searchCanaryBytes,
	)
}

// This is the public method for JS context analysis.
func (analyzer *HTMLScriptReflectionAnalyzer) AnalyzeJavaScriptContent(
	location ReflectionLocation,
	jsContent []byte,
	canaryToFind []byte,
	contentStartIndex int,
	contentEndIndex int,
) ReflectionOccurrenceDetail {

	zap.L().Debug("Entering AnalyzeInJavaScriptContext")
	scanIndex := contentStartIndex

	for scanIndex < contentEndIndex {
		tokenStartIndex := scanIndex

		currentSegmentType := byte(2)
		// Inner loop to determine token type based on character at current_scan_idx
		// current_scan_idx := currentIndex  // This was part of a more complex logic, simplified now
		// found_token_starter := false // This variable is not needed with the simplified logic below

		// or it will be incremented by 1 if the char at segmentStart was not a starter.
		// For simplicity and 1:1 mapping:

		for scanIndex < contentEndIndex {
			if jsContent[scanIndex] == charSingleQuote {
				currentSegmentType = 1
				break
			} else if jsContent[scanIndex] == charDoubleQuote {
				currentSegmentType = 0
				break
			} else if scanIndex+1 < contentEndIndex && jsContent[scanIndex] == charForwardSlash && jsContent[scanIndex+1] == charForwardSlash {
				currentSegmentType = 3
				break
			} else if scanIndex+1 < contentEndIndex && jsContent[scanIndex] == charForwardSlash && jsContent[scanIndex+1] == charAsterisk {
				currentSegmentType = 4
				scanIndex++
				break
			}
			scanIndex++
		}

		// Check if canary is in the segment that just got classified
		// ls.b is indexOf. So, check if canary is in the segment that just got classified (e.g. the '//' itself, or the quote char)
		// OR if tokenType is 2 (code), it checks in that code segment.
		if utils.IndexOfRangeCS(
			jsContent,
			canaryToFind,
			tokenStartIndex,
			scanIndex,
		) != -1 {
			// Reflection is in the JS code itself or within the token marker (or single code char)
			return NewReflectionPointCoreInfo(
				location,
				ReflectionContextJSCodeStatement,
				analyzer.reflectionInsertionPoint,
				tokenStartIndex+analyzer.sourceBodyOffset,
				analyzer.searchCanaryBytes,
			)
		}

		// If canary not in the segment/marker itself, proceed to find content
		tokenContentStartIndex := scanIndex + 1

		// tokenContentEndIndex is the index of the closing quote/comment end, or scriptContentEndOffset if not found or not applicable.
		tokenContentEndIndex := analyzer.findJavaScriptTokenEnd(
			jsContent,
			tokenContentStartIndex,
			contentEndIndex,
			currentSegmentType,
		)

		foundReflection := analyzer.findCanaryInJSSegment(
			location,
			jsContent,
			canaryToFind,
			tokenContentStartIndex,
			tokenContentEndIndex,
			currentSegmentType,
		)
		zap.L().Debug("reflection", zap.Any("foundReflection", foundReflection))
		if foundReflection != nil {
			return foundReflection
		}

		if currentSegmentType == 4 { // Block comment '/*'
			scanIndex = tokenContentEndIndex + 2 // Skip '*/'
		} else {
			scanIndex = tokenContentEndIndex + 1 // Skip closing quote or newline for line comment
		}
	}

	// Loop finished without finding reflection
	return NewReflectionPointCoreInfo(
		location,
		ReflectionContextJSCodeStatement,
		analyzer.reflectionInsertionPoint,
		contentStartIndex+analyzer.sourceBodyOffset,
		analyzer.searchCanaryBytes,
	)
}

func (analyzer *HTMLScriptReflectionAnalyzer) findCanaryInJSSegment(
	location ReflectionLocation,
	jsSegment []byte,
	canaryToFind []byte,
	segmentStartIndex int,
	segmentEndIndex int,
	segmentType byte,
) ReflectionOccurrenceDetail {
	if segmentType == 2 {
		return nil
	}
	// Check if canary exists in the segment
	if segmentStartIndex < segmentEndIndex &&
		utils.IndexOfRangeCS(
			jsSegment,
			canaryToFind,
			segmentStartIndex,
			segmentEndIndex,
		) != -1 {
		// log.Debugf("canaryToken: %s", string(canaryToken))
		// log.Debugf("contentStartOffset: %d", contentStartOffset)
		// log.Debugf("contentEndOffset: %d", contentEndOffset)
		// log.Debugf("tokenType: %d", tokenType)
		// Original content string where canary was found
		// Original content string where canary was found
		jsSegmentString := utils.BytesToStringInRange(
			jsSegment,
			segmentStartIndex,
			segmentEndIndex-segmentStartIndex,
		)

		// log.Debugf("originalContentString: %s", originalContentString)
		jsSegmentWithReplacedCanary := analyzer.replaceCanaryInJSStringValue(
			canaryToFind,
			jsSegmentString,
		)
		// log.Debugf("replacedContentString: %s", replacedContentString)

		reflectionPointStartIndex := segmentStartIndex + analyzer.sourceBodyOffset
		zap.L().Debug("reflectionPointLocation", zap.Int("location", reflectionPointStartIndex))

		var determinedContextType ReflectionContext
		switch segmentType {
		case 1: // Single-quoted string
			determinedContextType = ReflectionContextJSStringSQBreakout
		case 0: // Double-quoted string
			determinedContextType = ReflectionContextJSStringDQBreakout
		case 3: // Line comment //
			determinedContextType = ReflectionContextJSLineComment
		case 4: // Block comment /* */
			determinedContextType = ReflectionContextJSBlockComment
		default:
			return nil
		}
		zap.L().Debug("reflectionContext", zap.Int("contextType", int(determinedContextType)))

		reflectionInfo := NewReflectionPointCoreInfo(
			location,
			determinedContextType,
			analyzer.reflectionInsertionPoint,
			reflectionPointStartIndex,
			analyzer.searchCanaryBytes,
		)
		return NewJavaScriptContextReflection(reflectionInfo, jsSegmentWithReplacedCanary)
	}
	return nil
}

func (analyzer *HTMLScriptReflectionAnalyzer) replaceCanaryInAttributeValue(
	canary string,
	attr *htmlparser.HTMLAttribute,
) string {
	// Replace canary in attribute value with analyzer's canary bytes
	analyzerCanaryString := utils.BytesToString(analyzer.searchCanaryBytes)
	return strings.ReplaceAll(attr.Value, canary, analyzerCanaryString)
}

func (analyzer *HTMLScriptReflectionAnalyzer) replaceCanaryInJSStringValue(
	canaryToReplace []byte,
	jsStringValue string,
) string {
	// Replace canary in JS string value with analyzer's canary bytes
	stringToReplace := utils.BytesToString(canaryToReplace)
	analyzerCanaryString := utils.BytesToString(analyzer.searchCanaryBytes)
	return strings.ReplaceAll(jsStringValue, stringToReplace, analyzerCanaryString)
}

func (analyzer *HTMLScriptReflectionAnalyzer) findJavaScriptTokenEnd(
	jsData []byte,
	startIndex int,
	endIndex int,
	segmentType byte,
) int {
	scanIndex := startIndex

	for scanIndex < endIndex {
		// log.Debugf("currentChar: %s", string(dataToAnalyze[currentIndex]))
		if jsData[scanIndex] == charBackslash {
			scanIndex += 2 // Skip backslash and the escaped character
			continue
		}

		// Check for token end conditions
		isSegmentEndFound := false
		switch segmentType {
		case 1: // Single-quoted string
			if jsData[scanIndex] == charSingleQuote {
				isSegmentEndFound = true
			}
		case 0: // Double-quoted string
			if jsData[scanIndex] == charDoubleQuote {
				isSegmentEndFound = true
			}
		case 3: // Line comment //
			if jsData[scanIndex] == charLineFeed ||
				jsData[scanIndex] == charCR {
				isSegmentEndFound = true
			}
		case 4: // Block comment /* */
			if scanIndex+1 < endIndex && jsData[scanIndex] == charAsterisk &&
				jsData[scanIndex+1] == charForwardSlash {
				isSegmentEndFound = true
			}
		}

		if isSegmentEndFound {
			break // Break the for loop
		}

		scanIndex++
	}
	return scanIndex // Returns the index of the closing char, or searchEndOffset if not found
}

// HTMLTagInfoAdapter adapts HTMLTagInfo to the Dr2 interface.
type HTMLTagInfoAdapter struct {
	adapteeTagInfo *htmlparser.HTMLTagInfo
}

func NewHTMLTagInfoAdapter(tagInfo *htmlparser.HTMLTagInfo) *HTMLTagInfoAdapter {
	return &HTMLTagInfoAdapter{adapteeTagInfo: tagInfo}
}

func (w *HTMLTagInfoAdapter) IsHTMLTagInfoAccessor() {} // Marker method for interface

func (w *HTMLTagInfoAdapter) TagName() string {
	if w.adapteeTagInfo == nil {
		return ""
	}
	return w.adapteeTagInfo.Name
}

func (w *HTMLTagInfoAdapter) Attributes() []*htmlparser.HTMLAttribute {
	if w.adapteeTagInfo == nil {
		return nil
	}
	return w.adapteeTagInfo.Attributes
}

func (w *HTMLTagInfoAdapter) GetAttributeValue(
	attributeName string,
) string {
	if w.adapteeTagInfo == nil {
		return ""
	}
	for _, attr := range w.adapteeTagInfo.Attributes {
		if strings.EqualFold(attr.Name, attributeName) {
			return attr.Value
		}
	}
	return ""
}
