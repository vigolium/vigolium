package core

import "strings"

// It represents a reflection found in an HTTP header.
type HTTPHeaderReflection struct {
	coreInfo    *ReflectionPointCoreInfo
	headerName  string
	headerValue string
}

// NewHTTPHeaderReflection creates a new HTTPHeaderReflection.
func NewHTTPHeaderReflection(
	coreInfo *ReflectionPointCoreInfo,
	name string,
	value string,
) *HTTPHeaderReflection {
	return &HTTPHeaderReflection{coreInfo: coreInfo, headerName: name, headerValue: value}
}

// CoreInfo implements the ReflectionOccurrenceDetail interface, returning the core info associated with this reflection.
func (reflection *HTTPHeaderReflection) CoreInfo() *ReflectionPointCoreInfo {
	return reflection.coreInfo
}

// IsReflectionOccurrenceDetail marker method for ReflectionOccurrenceDetail interface.
func (reflection *HTTPHeaderReflection) IsReflectionOccurrenceDetail() {}

// Accept implements the ReflectionOccurrenceDetail interface, allowing a ReflectionDetailVisitor to visit this object.
func (reflection *HTTPHeaderReflection) Accept(visitor ReflectionDetailVisitor) interface{} {
	if visitor != nil {
		return visitor.VisitHTTPHeaderReflection(reflection)
	}
	return nil
}

// GetRedirectionTarget Returns redirection target info if applicable.
func (reflection *HTTPHeaderReflection) GetRedirectionTarget(
	detector *HTTPReflectionPointDetector,
) *RedirectionTargetInfo {
	if reflection.coreInfo == nil || detector == nil {
		return nil
	}
	httpStatusCode := detector.GetResponseStatusCode(
		reflection.coreInfo.location,
	)
	if httpStatusCode >= 300 && httpStatusCode < 400 &&
		strings.EqualFold(reflection.headerName, "location") {
		return NewRedirectDetails(
			RedirectTypeLocationHeader, // type
			reflection.headerValue,
			reflection.coreInfo.startIndexInInput,
			reflection.coreInfo.endIndexInInput,
			detector.GetContentBytes(reflection.coreInfo.location),
		)
	} else {
		if strings.EqualFold(reflection.headerName, "refresh") {
			urlStartIndex := strings.Index(strings.ToLower(reflection.headerValue), "url=")
			if urlStartIndex != -1 {
				urlStartIndex += 4 // Length of "url="
				return NewRedirectDetails(
					RedirectTypeRefreshHeaderURL, // type
					reflection.headerValue[urlStartIndex:],
					reflection.coreInfo.startIndexInInput+urlStartIndex,
					reflection.coreInfo.endIndexInInput,
					detector.GetContentBytes(reflection.coreInfo.location),
				)
			}
		}
		return nil
	}
}
