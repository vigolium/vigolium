package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
)

// It represents a reflection found within an HTML tag attribute, often a meta refresh.
type HTMLAttributeReflection struct {
	coreInfo       *ReflectionPointCoreInfo
	tagName        string
	attributeName  string
	attributeValue string
	htmlTagDetails *htmlparser.HTMLTagInfo
}

// NewHTMLAttributeReflection creates a new HTMLAttributeReflection instance.
func NewHTMLAttributeReflection(
	coreInfo *ReflectionPointCoreInfo,
	tagName string,
	attributeName string,
	attributeValue string,
	htmlTagDetails *htmlparser.HTMLTagInfo,
) *HTMLAttributeReflection {
	return &HTMLAttributeReflection{
		coreInfo:       coreInfo,
		tagName:        tagName,
		attributeName:  attributeName,
		attributeValue: attributeValue,
		htmlTagDetails: htmlTagDetails,
	}
}

// --- ReflectionOccurrenceDetail Interface Implementation ---

// CoreInfo implements the ReflectionOccurrenceDetail interface, returning the core info associated with this reflection.
func (reflection *HTMLAttributeReflection) CoreInfo() *ReflectionPointCoreInfo {
	return reflection.coreInfo
}

// IsReflectionOccurrenceDetail marker method for ReflectionOccurrenceDetail interface.
func (reflection *HTMLAttributeReflection) IsReflectionOccurrenceDetail() {}

// Accept implements the ReflectionOccurrenceDetail interface, allowing a ReflectionDetailVisitor to visit this object.
func (reflection *HTMLAttributeReflection) Accept(visitor ReflectionDetailVisitor) interface{} {
	if visitor != nil {
		return visitor.VisitHTMLAttributeReflection(reflection)
	}
	return nil
}

// GetRedirectionTarget Returns redirection target info if applicable.
func (reflection *HTMLAttributeReflection) GetRedirectionTarget(
	detector *HTTPReflectionPointDetector,
) *RedirectionTargetInfo {
	if reflection.coreInfo == nil || detector == nil || reflection.htmlTagDetails == nil {
		return nil
	}

	if strings.EqualFold(reflection.htmlTagDetails.Name, "meta") &&
		strings.EqualFold(reflection.htmlTagDetails.GetAttribute("http-equiv"), "refresh") &&
		strings.EqualFold(reflection.attributeName, "content") {

		urlStartIndex := strings.Index(strings.ToLower(reflection.attributeValue), "url=")
		if urlStartIndex != -1 {
			urlStartIndex += 4 // Length of "url="
			return NewRedirectDetails(
				RedirectTypeRefreshBodyURL, // type
				reflection.attributeValue[urlStartIndex:],
				reflection.coreInfo.startIndexInInput+urlStartIndex,
				reflection.coreInfo.endIndexInInput,
				detector.GetContentBytes(reflection.coreInfo.location),
			)
		}
	}
	return nil
}
