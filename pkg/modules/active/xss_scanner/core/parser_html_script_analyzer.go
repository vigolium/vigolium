package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// htmlEventHandlers corresponds to private static final String[] a in bca.java
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

// HTMLScriptReflectionAnalyzer corresponds to class bca in Java.
// Fields are named to match existing Go stub and mapped to Java fields:
// offsetD (Java: d) -> reflectionInsertionPointInFullInput
// offsetG (Java: c) -> dataToAnalyzeOffsetInFullInput
// canary (Java: e)  -> canaryTokenBytes
// activeTags (Java: b) -> currently open HTML tags relevant for context (script, xmp, etc.)
type HTMLScriptReflectionAnalyzer struct {
	reflectionInsertionPoint int    // Java: d
	sourceBodyOffset         int    // Java: c
	searchCanaryBytes        []byte // Java: e
	currentOpenTags          map[string]struct{}
}

// NewHTMLScriptReflectionAnalyzer is the constructor for BcaScriptAnalyzer.
// var1 (d in Java) -> reflectionInsertionPointInFullInput
// var2 (g in Java, c in Java's bca constructor) -> dataToAnalyzeOffsetInFullInput
// var3 (c in Go func signature, e in Java's bca constructor) -> canaryTokenBytes
func NewHTMLScriptReflectionAnalyzer(
	reflectionInsertionPoint int,
	sourceBodyOffset int,
	searchCanaryBytes []byte,
) *HTMLScriptReflectionAnalyzer {
	zap.L().Debug("NewBcaScriptAnalyzer",
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

// AnalyzeHTMLContext corresponds to bca.a(byte var1, byte[] var2, byte[] var3) in Java.
// It analyzes HTML-like content for reflections.
// contextIndicator (var1): Indicates the broader context of this analysis.
// dataToAnalyze (var2): The byte slice representing the content to be analyzed (e.g., an HTML document or fragment).
// canaryToken (var3): The byte slice representing the canary token we are searching for.
func (analyzer *HTMLScriptReflectionAnalyzer) AnalyzeHTMLContext(
	location ReflectionLocation,
	contentToAnalyze []byte,
	canaryToFind []byte,
) (ReflectionOccurrenceDetail, error) {
	zap.L().Debug("Entering AnalyzeGeneralContext",
		zap.Int("matchBytesRangeLen", len(contentToAnalyze)),
		zap.String("canaryToken", string(canaryToFind)))
	zap.L().Debug("BCA fields",
		zap.Int("startReflectionIdx", analyzer.reflectionInsertionPoint),
		zap.Int("startBodyOffsetInFullResponse", analyzer.sourceBodyOffset),
		zap.String("canaryTokenBytes", string(analyzer.searchCanaryBytes)))

	canaryStringTofind := utils.BytesToString(canaryToFind) // var5 in Java

	// bql.a(var2, 0, var2.length, (byte)0)
	// Assuming ParseHTMLElementsSimple provides similar functionality to bql.a for general parsing.
	// The last argument (byte)0 for bql.a might indicate a parsing mode or flags.
	// Using ParseModeFull as a general default.
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

	for _, currentElement := range parsedElements { // Corresponds to for (ahe var8 : var6)
		// boolean var9 = this.d >= var8.cR() + this.c && this.d < var8.cV() + this.c;
		// Trong Java: this.d là startIdx, this.c là endIdx (dựa trên constructor)
		// var8.cR() là htmlElement.StartOffset, var8.cV() là htmlElement.EndOffset

		// Thực tế, có thể Java đang sử dụng một cách tính offset khác.
		// Hãy giữ nguyên logic Java và xem kết quả:
		isInsertionPointInElement := analyzer.reflectionInsertionPoint >= (currentElement.StartOffset+analyzer.sourceBodyOffset) &&
			analyzer.reflectionInsertionPoint < (currentElement.EndOffset+analyzer.sourceBodyOffset)

		// QUAN TRỌNG: Sau khi phân tích kỹ, tôi hiểu rằng:
		// - bca.endIdx KHÔNG PHẢI là end offset của reflection
		// - bca.endIdx là bodyOffset (offset của body trong full response)
		// - Logic Java đang chuyển đổi offset từ patchedData sang full response
		//
		// Trong Go, chúng ta không có full response offset, chỉ có body offset.
		// Vì vậy, cần điều chỉnh logic:
		// - Nếu canary được tìm thấy trong element, thì reflection nằm trong element đó
		// - Đây là cách đơn giản và chính xác nhất cho Go

		// Override logic nếu tìm thấy canary trong element
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
					// if (var8.cS().a4().contains(var5))
					if strings.Contains(currentElement.TagInfo.Name, canaryStringTofind) {
						// return new hpo(var1, (byte)2, this.d, var8.cR() + this.c, this.e);
						return NewReflectionPointCoreInfo(
							location,
							ReflectionContextHTMLTagCloseAndInject,
							analyzer.reflectionInsertionPoint,
							currentElement.StartOffset+analyzer.sourceBodyOffset, // var8.cR() + this.c
							analyzer.searchCanaryBytes,
						), nil
					}

					for _, currentAttribute := range currentElement.TagInfo.Attributes {
						// if (var11.cV().contains(var5))
						if strings.Contains(currentAttribute.Name, canaryStringTofind) {
							// return new fcp(new reflectionInfo(var1, (byte)3, this.d, var11.cW() + this.c, this.e), var8.cS().a4(), "", "", var8.cS());
							reflectionInfo := NewReflectionPointCoreInfo(
								location,
								ReflectionContextHTMLAttributeName,
								analyzer.reflectionInsertionPoint,
								currentAttribute.NameStart+analyzer.sourceBodyOffset, // var11.cW() + this.c
								analyzer.searchCanaryBytes,
							)
							// Ensure TagInfo is passed correctly. If htmlElement.TagInfo is nil, this would panic. Handled by outer nil check.
							return NewHTMLAttributeReflection(
								reflectionInfo,
								currentElement.TagInfo.Name,
								"",
								"",
								currentElement.TagInfo,
							), nil // dr2 is TagInfo
						}

						// if (var11.cY().contains(var5))
						if strings.Contains(currentAttribute.Value, canaryStringTofind) {
							// eqx var12 = this.a(var1, var8, var11, var5);
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
				// return new hpo(var1, (byte)23, this.d, var8.cR() + this.c, this.e);
				return NewReflectionPointCoreInfo(
					location,
					ReflectionContextHTMLCommentBreakout,
					analyzer.reflectionInsertionPoint,
					currentElement.StartOffset+analyzer.sourceBodyOffset, // var8.cR() + this.c
					analyzer.searchCanaryBytes,
				), nil
			}

		case htmlparser.TextNode: // Case 3
			if isInsertionPointInElement {
				// return this.b(var1, var2, var3, var8.cR(), var8.cV());
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

	// Debug active tags trước khi return
	zap.L().Debug("Active tags at end of AnalyzeGeneralContext", zap.Any("activeTags", analyzer.currentOpenTags))

	return nil, nil
}

// analyzeReflectionInHTMLAttribute corresponds to private eqx a(byte var1, ahe var2, ffv var3, String var4)
func (analyzer *HTMLScriptReflectionAnalyzer) analyzeReflectionInHTMLAttribute(
	location ReflectionLocation,
	element *htmlparser.HTMLElement, // var2 (ahe)
	attr *htmlparser.HTMLAttribute, // var3 (ffv)
	canary string, // var4
) ReflectionOccurrenceDetail {
	isURLAttributeType := analyzer.isAttributeURLType(element, attr) // var6
	isEventHandlerAttributeType := false                             // var7

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

	// String var12 = this.a(var4, var3);
	attributeValueWithReplacedCanary := analyzer.replaceCanaryInAttributeValue(canary, attr)

	var determinedContextType ReflectionContext
	attrQuoteType := attr.QuoteType // ffv.cZ() -> HTMLAttribute.QuoteType

	if isURLAttributeType {
		switch attrQuoteType {
		case htmlparser.QuoteTypeDouble: // 0 in Java
			determinedContextType = ReflectionContextJSInURLAttributeDQ
		case htmlparser.QuoteTypeSingle: // 1 in Java
			determinedContextType = ReflectionContextJSInURLAttributeSQ
		case htmlparser.QuoteTypeBacktick: // 2 in Java
			determinedContextType = ReflectionContextJSInURLAttributeBT
		case htmlparser.QuoteTypeNone: // 3 in Java
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

	// reflectionInfo := new reflectionInfo(var1, (byte)(...), this.d, var3.c0() + this.c, this.e)
	// var3.c0() is attribute.ValueStart
	reflectionInfo := NewReflectionPointCoreInfo(
		location,
		determinedContextType,
		analyzer.reflectionInsertionPoint,
		attr.ValueStart+analyzer.sourceBodyOffset,
		analyzer.searchCanaryBytes,
	)

	// return new fcp(hpo, var2.cS().a4(), var3.cV(), var12, var2.cS());
	// var2.cS() is containingElement.TagInfo
	// var2.cS().a4() is containingElement.TagInfo.Name
	// var3.cV() is attribute.Name
	if element.TagInfo == nil {
		// This case should ideally not happen if attribute exists, but good for safety.
		// Java might throw NPE here if var2.cS() is null.
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

// isAttributeURLType corresponds to private boolean a(ahe var1, ffv var2)
func (analyzer *HTMLScriptReflectionAnalyzer) isAttributeURLType(
	element *htmlparser.HTMLElement,
	attr *htmlparser.HTMLAttribute,
) bool {
	if element.TagInfo == nil {
		return false // Cannot determine if TagInfo is missing
	}
	currentTagName := element.TagInfo.Name // var3 = var1.cS().a4()
	currentAttributeName := attr.Name      // var4 = var2.cV()

	// if (!"src".equalsIgnoreCase(var4) && !"data".equalsIgnoreCase(var4) || !"iframe".equalsIgnoreCase(var3) && !"object".equalsIgnoreCase(var3) && !"embed".equalsIgnoreCase(var3) && !"frame".equalsIgnoreCase(var3))
	if (!strings.EqualFold("src", currentAttributeName) && !strings.EqualFold("data", currentAttributeName)) ||
		(!strings.EqualFold("iframe", currentTagName) && !strings.EqualFold("object", currentTagName) && !strings.EqualFold("embed", currentTagName) && !strings.EqualFold("frame", currentTagName)) {
		// if (!"href".equalsIgnoreCase(var4) || !"a".equalsIgnoreCase(var3) && !"math".equalsIgnoreCase(var3))
		if !strings.EqualFold("href", currentAttributeName) ||
			(!strings.EqualFold("a", currentTagName) && !strings.EqualFold("math", currentTagName)) {
			// return !"formaction".equalsIgnoreCase(var4) || !"button".equalsIgnoreCase(var3) && !"input".equalsIgnoreCase(var3) ? "action".equalsIgnoreCase(var4) && "form".equalsIgnoreCase(var3) : true;
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

// updateCurrentOpenTags corresponds to private void a(ahe var1)
func (analyzer *HTMLScriptReflectionAnalyzer) updateCurrentOpenTags(
	element *htmlparser.HTMLElement,
) {
	// int var2 = hpo.c(); // hpoLoopControl, always 82. Not directly used in this method's core logic flow for breaks.

	if element.TagInfo == nil {
		return
	}
	lowerCaseTagName := strings.ToLower(element.TagInfo.Name)

	// if (var1.cU() == 1) // CloseTag
	if element.Type == htmlparser.CloseTag {
		delete(analyzer.currentOpenTags, lowerCaseTagName)
		// if (var2 != 0) { return; } // var2 is 82. 82 != 0 is true. This return is LIVE.
		// This means if it's a close tag, it removes and then returns.
		return // Mirrored Java logic
	}

	// This part is for OpenTag or SelfClosingTagOrPI (implicitly, as it's not CloseTag and didn't return)
	analyzer.currentOpenTags[lowerCaseTagName] = struct{}{}
	// Original Java does not have an 'else' or further conditions based on var2 here,
	// so the `if (var2 != 0)` check in the Java if-block seems to only affect the CloseTag case.
}

// analyzeTextNodeInSpecialTag corresponds to private eqx b(byte var1, byte[] var2, byte[] var3, int var4, int var5)
func (analyzer *HTMLScriptReflectionAnalyzer) analyzeTextNodeInSpecialTag(
	location ReflectionLocation, // var1
	fullContent []byte, // var2
	canary []byte, // var3
	nodeStartIndex int, // var4 - relative to dataToAnalyze
	nodeEndIndex int, // var5 - relative to dataToAnalyze
) ReflectionOccurrenceDetail {
	// this.d is reflectionInsertionPointInFullInput
	// this.c is dataToAnalyzeOffsetInFullInput
	// this.e is canaryTokenBytes
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

// AnalyzeJavaScriptContent corresponds to bca.a(byte var1, byte[] var2, byte[] var3, int var4, int var5)
// This is the public method for JS context analysis.
func (analyzer *HTMLScriptReflectionAnalyzer) AnalyzeJavaScriptContent(
	location ReflectionLocation, // var1
	jsContent []byte, // var2
	canaryToFind []byte, // var3
	contentStartIndex int, // var4
	contentEndIndex int, // var5
) ReflectionOccurrenceDetail {

	zap.L().Debug("Entering AnalyzeInJavaScriptContext")
	scanIndex := contentStartIndex // var7 in Java

	for scanIndex < contentEndIndex { // while (var7 < var5)
		tokenStartIndex := scanIndex // var8 in Java (stores current var7 before inner loop)

		// var9 in Java (2: default/code, 0: double-quoted string, 1: single-quoted string, 3: line comment, 4: block comment)
		currentSegmentType := byte(2)
		// Inner loop to determine token type based on character at current_scan_idx
		// In Java, var7 is advanced by this inner loop.
		// Since hpoBControl (var6) is always 0, any "if (var6 == 0) { break; }" is a LIVE break.
		// Any "if (var6 != 0) { break; }" is a DEAD break.
		// current_scan_idx := currentIndex  // This was part of a more complex logic, simplified now
		// found_token_starter := false // This variable is not needed with the simplified logic below

		// The Java inner while loop advances var7 until a token starter or end of script.
		// Given var6 == 0 makes breaks live, the inner Java loop effectively does this:
		// 1. Check char at var7 (our currentIndex).
		// 2. If it's a token starter (', ", //, /*), set var9, advance var7 past starter, then BREAK inner loop.
		// 3. If not a starter, var7++, then if var6!=0 (false) break (DEAD), so continue inner loop.
		// This means var7 (current_scan_idx here) will point to the char *after* the recognized token starter,
		// or it will be incremented by 1 if the char at segmentStart was not a starter.
		// For simplicity and 1:1 mapping:

		for scanIndex < contentEndIndex {
			if jsContent[scanIndex] == 39 { // 39
				currentSegmentType = 1
				break
			} else if jsContent[scanIndex] == 34 { // 34
				currentSegmentType = 0
				break
			} else if scanIndex+1 < contentEndIndex && jsContent[scanIndex] == 47 && jsContent[scanIndex+1] == 47 { // 47, 47
				currentSegmentType = 3
				break
			} else if scanIndex+1 < contentEndIndex && jsContent[scanIndex] == 47 && jsContent[scanIndex+1] == 42 { // 47, 42
				currentSegmentType = 4
				scanIndex++
				break
			}
			scanIndex++
		}

		// byte[] var10000 = var2; byte[] var10001 = var3; int var10002 = var8; int var10003 = var7 (updated);
		// if (net.portswigger.ls.b(var2, var3, segmentStart, idx_after_token_marker_detection) != -1) {
		// ls.b is indexOf. So, check if canary is in the segment that just got classified (e.g. the '//' itself, or the quote char)
		// OR if tokenType is 2 (code), it checks in that code segment.
		// The Java code performs a single check here on the segment [segmentStart, idx_after_token_marker_detection).
		if utils.NetPortswiggerLsBIndexOfRangeCS(
			jsContent,
			canaryToFind,
			tokenStartIndex,
			scanIndex,
		) != -1 {
			// return new hpo(var1, (byte)18, this.d, var8 + this.c, this.e);
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
		// var8 = ++var7; (Java) -> tokenContentStartIndex = idx_after_token_marker_detection (if we take var7 as idx_after_token_marker_detection before this line)
		tokenContentStartIndex := scanIndex + 1

		// var7 = var17.a(var2, segmentStartForContent, scriptContentEndOffset, tokenType);
		// tokenContentEndIndex is the index of the closing quote/comment end, or scriptContentEndOffset if not found or not applicable.
		tokenContentEndIndex := analyzer.findJavaScriptTokenEnd(
			jsContent,
			tokenContentStartIndex,
			contentEndIndex,
			currentSegmentType,
		)

		// eqx var10 = this.a(var1, var2, var3, segmentStartForContent, endOfTokenContent, tokenType);
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

		// Advance current_idx (Java's var7) for the next iteration of the outer loop
		// label52: { if (var9 == 4) { var7 += 2; if (var6 == 0) { break label52;} } var7++; }
		// Since var6 (hpoBControl) is 0, the "if (var6 == 0) { break label52;}" means it will take the var7+=2 or var7++ path.
		if currentSegmentType == 4 { // Block comment '/*'
			scanIndex = tokenContentEndIndex + 2 // Skip '*/'
		} else {
			scanIndex = tokenContentEndIndex + 1 // Skip closing quote or newline for line comment
		}
		// if (var6 == 0) { continue; } -> This is true (0==0), so continue outer loop.
		// break; -> This is for a hypothetical outer "if (var6 != 0)" which is false. So this break is DEAD.
	}

	// Loop finished without finding reflection
	// return new hpo(var1, (byte)18, this.d, var4 + this.c, this.e); // Fallback, reflection at start of script
	return NewReflectionPointCoreInfo(
		location,
		ReflectionContextJSCodeStatement,
		analyzer.reflectionInsertionPoint,
		contentStartIndex+analyzer.sourceBodyOffset,
		analyzer.searchCanaryBytes,
	)
}

// findCanaryInJSSegment corresponds to private eqx a(byte var1, byte[] var2, byte[] var3, int var4, int var5, byte var6)
// var4: contentStartOffset, var5: contentEndOffset, var6: tokenType
func (analyzer *HTMLScriptReflectionAnalyzer) findCanaryInJSSegment(
	location ReflectionLocation, // var1
	jsSegment []byte, // var2
	canaryToFind []byte, // var3
	segmentStartIndex int, // var4
	segmentEndIndex int, // var5
	segmentType byte, // var6
) ReflectionOccurrenceDetail {
	if segmentType == 2 {
		return nil
	}
	// if (net.portswigger.ls.b(var2, var3, var4, var5) != -1)
	if segmentStartIndex < segmentEndIndex &&
		utils.NetPortswiggerLsBIndexOfRangeCS(
			jsSegment,
			canaryToFind,
			segmentStartIndex,
			segmentEndIndex,
		) != -1 {
		// log.Debugf("canaryToken: %s", string(canaryToken))
		// log.Debugf("contentStartOffset: %d", contentStartOffset)
		// log.Debugf("contentEndOffset: %d", contentEndOffset)
		// log.Debugf("tokenType: %d", tokenType)
		// String var7 = net.portswigger.h9.a(var2, var4, var5 - var4);
		// Original content string where canary was found
		jsSegmentString := utils.BytesToStringInRange(
			jsSegment,
			segmentStartIndex,
			segmentEndIndex-segmentStartIndex,
		)

		// log.Debugf("originalContentString: %s", originalContentString)
		// var7 = this.a(var3, var7); // Replace canary in that string
		jsSegmentWithReplacedCanary := analyzer.replaceCanaryInJSStringValue(
			canaryToFind,
			jsSegmentString,
		)
		// log.Debugf("replacedContentString: %s", replacedContentString)

		// Calculate HPO insertion point (this.d) and the specific location within JS (var4 + this.c)
		reflectionPointStartIndex := segmentStartIndex + analyzer.sourceBodyOffset
		zap.L().Debug("hpoReflectionLocation", zap.Int("location", reflectionPointStartIndex))

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

// replaceCanaryInAttributeValue corresponds to private String a(String var1, ffv var2)
func (analyzer *HTMLScriptReflectionAnalyzer) replaceCanaryInAttributeValue(
	canary string,
	attr *htmlparser.HTMLAttribute,
) string {
	// return var2.cY().replace(var1, net.portswigger.h9.a(this.e));
	// var2.cY() is attribute.Value
	// var1 is canaryString
	// net.portswigger.h9.a(this.e) is string representation of bca.canaryTokenBytes
	analyzerCanaryString := utils.BytesToString(analyzer.searchCanaryBytes)
	return strings.ReplaceAll(attr.Value, canary, analyzerCanaryString)
}

// replaceCanaryInJSStringValue corresponds to private String a(byte[] var1, String var2)
func (analyzer *HTMLScriptReflectionAnalyzer) replaceCanaryInJSStringValue(
	canaryToReplace []byte,
	jsStringValue string,
) string {
	// return var2.replace(net.portswigger.h9.a(var1), net.portswigger.h9.a(this.e));
	// net.portswigger.h9.a(var1) is string from canaryToken
	// net.portswigger.h9.a(this.e) is string from bca.canaryTokenBytes
	stringToReplace := utils.BytesToString(canaryToReplace)
	analyzerCanaryString := utils.BytesToString(analyzer.searchCanaryBytes)
	return strings.ReplaceAll(jsStringValue, stringToReplace, analyzerCanaryString)
}

// findJavaScriptTokenEnd corresponds to private int a(byte[] var1, int var2, int var3, byte var4)
// var1: dataToAnalyze, var2: searchStartOffset, var3: searchEndOffset (exclusive), var4: tokenType
func (analyzer *HTMLScriptReflectionAnalyzer) findJavaScriptTokenEnd(
	jsData []byte,
	startIndex int,
	endIndex int,
	segmentType byte,
) int {
	scanIndex := startIndex // var2 in Java

	for scanIndex < endIndex { // while (var2 < var3)
		// log.Debugf("currentChar: %s", string(dataToAnalyze[currentIndex]))
		if jsData[scanIndex] == 92 { // 92
			scanIndex += 2 // Skip backslash and the escaped character
			// if (var5 == 0) { continue; } // var5 is 0. 0 == 0 is true. So, continue.
			continue
		}

		// Check for token end conditions
		isSegmentEndFound := false
		switch segmentType {
		case 1: // Single-quoted string
			if jsData[scanIndex] == 39 { // '
				isSegmentEndFound = true
			}
		case 0: // Double-quoted string
			if jsData[scanIndex] == 34 { // "
				isSegmentEndFound = true
			}
		case 3: // Line comment //
			if jsData[scanIndex] == 10 ||
				jsData[scanIndex] == 13 { // \n or \r
				isSegmentEndFound = true
			}
		case 4: // Block comment /* */
			if scanIndex+1 < endIndex && jsData[scanIndex] == 42 &&
				jsData[scanIndex+1] == 47 { // /* or */
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

func (w *HTMLTagInfoAdapter) TagName() string { // Corresponds to dr2.a4() -> tag name
	if w.adapteeTagInfo == nil {
		return ""
	}
	return w.adapteeTagInfo.Name
}

func (w *HTMLTagInfoAdapter) Attributes() []*htmlparser.HTMLAttribute { // Corresponds to dr2.a5() -> list of attributes
	if w.adapteeTagInfo == nil {
		return nil
	}
	return w.adapteeTagInfo.Attributes
}

func (w *HTMLTagInfoAdapter) GetAttributeValue(
	attributeName string,
) string { // Corresponds to dr2.e(String) -> get attribute value by name
	if w.adapteeTagInfo == nil {
		return ""
	}
	for _, attr := range w.adapteeTagInfo.Attributes {
		if strings.EqualFold(attr.Name, attributeName) {
			return attr.Value
		}
	}
	return "" // Or based on Java's behavior for missing attribute
}
