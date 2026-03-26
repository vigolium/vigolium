package core

import "strings"

// HTTPHeaderReflection is a Go equivalent of the Java class e1t.
// It represents a reflection found in an HTTP header.
type HTTPHeaderReflection struct {
	coreInfo    *ReflectionPointCoreInfo // Corresponds to 'public final hpo b;' in Java
	headerName  string                   // Corresponds to 'public final String c;' (header name)
	headerValue string                   // Corresponds to 'public final String a;' (header value)
}

// NewHTTPHeaderReflection creates a new E1tReflectionDetail.
// Corresponds to e1t(hpo var1, String var2, String var3)
func NewHTTPHeaderReflection(
	coreInfo *ReflectionPointCoreInfo,
	name string,
	value string,
) *HTTPHeaderReflection {
	return &HTTPHeaderReflection{coreInfo: coreInfo, headerName: name, headerValue: value}
}

// CoreInfo implements the Eqx interface, returning the Hpo associated with this reflection.
// Corresponds to e1t.a() which returns hpo.
func (reflection *HTTPHeaderReflection) CoreInfo() *ReflectionPointCoreInfo {
	return reflection.coreInfo
}

// IsReflectionOccurrenceDetail marker method for Eqx interface.
func (reflection *HTTPHeaderReflection) IsReflectionOccurrenceDetail() {}

// Accept implements the Eqx interface, allowing an EnaVisitor to visit this object.
func (reflection *HTTPHeaderReflection) Accept(visitor ReflectionDetailVisitor) interface{} {
	if visitor != nil {
		return visitor.VisitE1t(reflection) // Call the EnaVisitor's method for E1tReflectionDetail
	}
	return nil
}

// GetRedirectionTarget corresponds to eqx.a(crp) - Method to get Dw9 redirection info
// Ported from e1t.java public dw9 a(crp var1)
func (reflection *HTTPHeaderReflection) GetRedirectionTarget(
	detector *HTTPReflectionPointDetector,
) *RedirectionTargetInfo {
	if reflection.coreInfo == nil || detector == nil {
		return nil
	}
	// short var2 = var1.c(this.b.d);
	httpStatusCode := detector.GetResponseStatusCode(
		reflection.coreInfo.location,
	) // hpo.d is ContextIndicator

	// if (var2 >= 300 && var2 < 400 && "location".equalsIgnoreCase(this.c))
	if httpStatusCode >= 300 && httpStatusCode < 400 &&
		strings.EqualFold(reflection.headerName, "location") {
		// return new dw9((byte)0, this.a, this.b.f, this.b.c, var1.a(this.b.d));
		// this.a is HeaderValueVal
		// this.b.f is HpoVal.ReflectionStartInInput
		// this.b.c is HpoVal.ReflectionEndInInput
		// var1.a(this.b.d) is crpCtx.AByteReturnBytes(e.HpoVal.ContextIndicator)
		return NewRedirectDetails(
			RedirectTypeLocationHeader, // type
			reflection.headerValue,
			reflection.coreInfo.startIndexInInput,
			reflection.coreInfo.endIndexInInput,
			detector.GetContentBytes(reflection.coreInfo.location),
		)
	} else {
		// if ("refresh".equalsIgnoreCase(this.c))
		if strings.EqualFold(reflection.headerName, "refresh") {
			// e1t var10000 = this;
			// int var3 = var10000.a.toLowerCase().indexOf("url=");
			urlStartIndex := strings.Index(strings.ToLower(reflection.headerValue), "url=")
			if urlStartIndex != -1 {
				urlStartIndex += 4 // Length of "url="
				// return new dw9((byte)1, this.a.substring(var3), this.b.f + var3, this.b.c, var1.a(this.b.d));
				return NewRedirectDetails(
					RedirectTypeRefreshHeaderURL, // type
					reflection.headerValue[urlStartIndex:],
					reflection.coreInfo.startIndexInInput+urlStartIndex,
					reflection.coreInfo.endIndexInInput,
					detector.GetContentBytes(reflection.coreInfo.location),
				)
			}
			// Original Java code has a try-catch for Exception around indexOf and substring,
			// In Go, string operations don't throw exceptions
			// but out-of-bounds slicing will panic. Index() returning -1 is handled.
		}
		return nil
	}
}
