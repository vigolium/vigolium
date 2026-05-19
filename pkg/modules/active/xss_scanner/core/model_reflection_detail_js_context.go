package core

import "strings"

// JavaScriptContextReflection represents a reflection found in a JavaScript context, often leading to a redirect.
type JavaScriptContextReflection struct {
	coreInfo *ReflectionPointCoreInfo
	jsValue  string
}

// NewJavaScriptContextReflection creates a new JavaScriptContextReflection instance.
func NewJavaScriptContextReflection(
	coreInfo *ReflectionPointCoreInfo,
	jsValue string,
) *JavaScriptContextReflection {
	return &JavaScriptContextReflection{
		coreInfo: coreInfo,
		jsValue:  jsValue,
	}
}

// --- ReflectionOccurrenceDetail Interface Implementation ---

// CoreInfo implements the ReflectionOccurrenceDetail interface, returning the core info associated with this reflection.
func (reflection *JavaScriptContextReflection) CoreInfo() *ReflectionPointCoreInfo {
	return reflection.coreInfo
}

// IsReflectionOccurrenceDetail marker method for ReflectionOccurrenceDetail interface.
func (reflection *JavaScriptContextReflection) IsReflectionOccurrenceDetail() {}

// Accept implements the ReflectionOccurrenceDetail interface, allowing a ReflectionDetailVisitor to visit this object.
func (reflection *JavaScriptContextReflection) Accept(visitor ReflectionDetailVisitor) interface{} {
	if visitor != nil {
		return visitor.VisitJavaScriptContextReflection(reflection)
	}
	return nil
}

// GetRedirectionTarget Returns redirection target info if applicable.
func (reflection *JavaScriptContextReflection) GetRedirectionTarget(
	detector *HTTPReflectionPointDetector,
) *RedirectionTargetInfo {
	if reflection.coreInfo == nil || detector == nil {
		return nil
	}

	contextSearchStartIndex := reflection.coreInfo.startIndexInInput - 30
	if contextSearchStartIndex < 0 {
		contextSearchStartIndex = 0
	}

	responseContentBytes := detector.GetContentBytes(reflection.coreInfo.location)
	if responseContentBytes == nil {
		return nil // Cannot proceed without source bytes
	}

	var contextStringBuilder strings.Builder
	// Ensure loop does not go out of bounds of sourceBytes
	searchBoundaryEndIndex := reflection.coreInfo.startIndexInInput
	if searchBoundaryEndIndex > len(
		responseContentBytes,
	) { // Cap loopEnd to sourceBytes length if HpoVal.f is too large
		searchBoundaryEndIndex = len(responseContentBytes)
	}
	if contextSearchStartIndex > searchBoundaryEndIndex { // If start is already past capped end
		contextSearchStartIndex = searchBoundaryEndIndex
	}

	for currentIndex := contextSearchStartIndex; currentIndex < searchBoundaryEndIndex; currentIndex++ {
		currentChar := rune(
			responseContentBytes[currentIndex],
		) // Convert byte to rune to check IsLetter
		if (currentChar >= 'a' && currentChar <= 'z') ||
			(currentChar >= 'A' && currentChar <= 'Z') { // Basic IsLetter for ASCII
			contextStringBuilder.WriteRune(currentChar)
		}
	}

	extractedContextString := strings.ToLower(contextStringBuilder.String())

	if !strings.HasSuffix(extractedContextString, "documentlocation") &&
		!strings.HasSuffix(extractedContextString, "documenturl") &&
		!strings.HasSuffix(extractedContextString, "windowopen") &&
		!strings.HasSuffix(extractedContextString, "windownavigate") &&
		!strings.HasSuffix(extractedContextString, "locationhref") {
		return nil
	} else {
		return NewRedirectDetails(
			RedirectTypeJavaScript, // type
			reflection.jsValue,
			reflection.coreInfo.startIndexInInput,
			reflection.coreInfo.endIndexInInput,
			responseContentBytes, // The full sourceBytes, not just the scanned part for contextString
		)
	}
}
