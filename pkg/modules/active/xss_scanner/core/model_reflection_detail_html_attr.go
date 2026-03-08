package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
)

// HTMLAttributeReflection is a Go equivalent of the Java class fcp.
// It represents a reflection found within an HTML tag attribute, often a meta refresh.
type HTMLAttributeReflection struct {
	coreInfo       *ReflectionPointCoreInfo // Corresponds to 'public final hpo c;'
	tagName        string                   // Corresponds to 'public final String d;' (e.g., "meta")
	attributeName  string                   // Corresponds to 'public final String b;' (e.g., "content")
	attributeValue string                   // Corresponds to 'public final String e;' (value of the attribute)
	htmlTagDetails *htmlparser.HTMLTagInfo  // Corresponds to 'public final dr2 a;' (info about the HTML tag)
}

// NewHTMLAttributeReflection creates a new FcpReflectionDetail instance.
// Corresponds to fcp(hpo var1, String var2, String var3, String var4, dr2 var5)
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

// --- Eqx Interface Implementation for FcpReflectionDetail ---

// CoreInfo implements the Eqx interface, returning the Hpo associated with this reflection.
// Corresponds to fcp.a() which returns hpo.
func (reflection *HTMLAttributeReflection) CoreInfo() *ReflectionPointCoreInfo {
	return reflection.coreInfo
}

// IsReflectionOccurrenceDetail marker method for Eqx interface.
func (reflection *HTMLAttributeReflection) IsReflectionOccurrenceDetail() {}

// Accept implements the Eqx interface, allowing an EnaVisitor to visit this object.
func (reflection *HTMLAttributeReflection) Accept(visitor ReflectionDetailVisitor) interface{} {
	if visitor != nil {
		return visitor.VisitFcp(reflection) // Call the EnaVisitor's method for FcpReflectionDetail
	}
	return nil
}

// GetRedirectionTarget corresponds to eqx.a(crp) - Method to get Dw9 redirection info.
// Ported from fcp.java public dw9 a(crp var1)
func (reflection *HTMLAttributeReflection) GetRedirectionTarget(
	detector *HTTPReflectionPointDetector,
) *RedirectionTargetInfo {
	if reflection.coreInfo == nil || detector == nil || reflection.htmlTagDetails == nil {
		return nil
	}

	// if ("meta".equalsIgnoreCase(this.a.a4()) &&
	//     "refresh".equalsIgnoreCase(this.a.e("http-equiv")) &&
	//     "content".equalsIgnoreCase(this.b))
	if strings.EqualFold(reflection.htmlTagDetails.Name, "meta") &&
		strings.EqualFold(reflection.htmlTagDetails.GetAttribute("http-equiv"), "refresh") &&
		strings.EqualFold(reflection.attributeName, "content") {

		// int var2 = var10000.e.toLowerCase().indexOf("url="); // this.e is AttributeValueVal
		urlStartIndex := strings.Index(strings.ToLower(reflection.attributeValue), "url=")
		if urlStartIndex != -1 {
			urlStartIndex += 4 // Length of "url="
			// return new dw9((byte)2, this.e.substring(var2), this.c.f + var2, this.c.c, var1.a(this.c.d));
			// this.c.f is HpoVal.ReflectionStartInInput
			// this.c.c is HpoVal.ReflectionEndInInput
			// var1.a(this.c.d) is crpCtx.AByteReturnBytes(f.HpoVal.ContextIndicator)
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
