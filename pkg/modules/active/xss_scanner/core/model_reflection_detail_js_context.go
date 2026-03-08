package core

import "strings"

// Note: HpoReflectionPoint, Dw9ReflectionTarget would be defined in stubs.go or their respective files
// For now, assuming they are compatible with Hpo and Dw9 interfaces/structs expected.
// Make sure HpoReflectionPoint has GetContextIndicator(), GetStartOffset(), GetEndOffset(), GetCanary()
// Make sure Eqx has A_Crp(Crp) *Dw9ReflectionTarget (or similar)

// JavaScriptContextReflection is a Go equivalent of the Java class fcg.
// It represents a reflection found in a JavaScript context, often leading to a redirect.
type JavaScriptContextReflection struct {
	coreInfo *ReflectionPointCoreInfo // Corresponds to 'public final hpo a;'
	jsValue  string                   // Corresponds to 'public final String b;' (e.g., the URL part in document.location = ...)
}

// NewJavaScriptContextReflection creates a new FcgReflectionDetail instance.
// Corresponds to fcg(hpo var1, String var2)
func NewJavaScriptContextReflection(
	coreInfo *ReflectionPointCoreInfo,
	jsValue string,
) *JavaScriptContextReflection {
	return &JavaScriptContextReflection{
		coreInfo: coreInfo,
		jsValue:  jsValue,
	}
}

// --- Eqx Interface Implementation for FcgReflectionDetail ---

// CoreInfo implements the Eqx interface, returning the Hpo associated with this reflection.
// Corresponds to fcg.a() which returns hpo.
func (reflection *JavaScriptContextReflection) CoreInfo() *ReflectionPointCoreInfo {
	return reflection.coreInfo
}

// IsReflectionOccurrenceDetail marker method for Eqx interface.
func (reflection *JavaScriptContextReflection) IsReflectionOccurrenceDetail() {}

// Accept implements the Eqx interface, allowing an EnaVisitor to visit this object.
func (reflection *JavaScriptContextReflection) Accept(visitor ReflectionDetailVisitor) interface{} {
	if visitor != nil {
		return visitor.VisitFcg(reflection) // Call the EnaVisitor's method for FcgReflectionDetail
	}
	return nil
}

// GetRedirectionTarget corresponds to eqx.a(crp) - Method to get Dw9 redirection info.
// Ported from fcg.java public dw9 a(crp var1)
func (reflection *JavaScriptContextReflection) GetRedirectionTarget(
	detector *HTTPReflectionPointDetector,
) *RedirectionTargetInfo {
	if reflection.coreInfo == nil || detector == nil {
		return nil
	}

	// Original Java: int var2 = hpo.b();
	// hpo.b() (HpoStaticGetB in Go) effectively returns 0 due to obfuscation patterns.
	// This `var2` is used in a loop's conditional break: `if (var2 != 0) break;`.
	// Since `var2` is 0, `var2 != 0` is always false. The break is dead code.
	// This Go implementation correctly omits this dead break and does not need to call HpoStaticGetB().
	// loopControlHpoB := HpoStaticGetB() // This call is removed.

	// int var3 = this.a.f - 30; // HpoVal.ReflectionStartInInput - 30
	contextSearchStartIndex := reflection.coreInfo.startIndexInInput - 30
	if contextSearchStartIndex < 0 {
		contextSearchStartIndex = 0
	}

	// byte[] var5 = var1.a(this.a.d); // responseContentBytes = crpCtx.AByteReturnBytes(HpoVal.ContextIndicator)
	responseContentBytes := detector.GetContentBytes(reflection.coreInfo.location)
	if responseContentBytes == nil {
		return nil // Cannot proceed without source bytes
	}

	var contextStringBuilder strings.Builder
	// int var6 = var3; // loopIndex = startIndexForSearch
	// while (var6 < this.a.f) // Loop up to HpoVal.ReflectionStartInInput (f.HpoVal.GetF())
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
		// char var7 = (char)var5[var6];
		currentChar := rune(
			responseContentBytes[currentIndex],
		) // Convert byte to rune to check IsLetter
		// if (Character.isLetter(var7))
		if (currentChar >= 'a' && currentChar <= 'z') ||
			(currentChar >= 'A' && currentChar <= 'Z') { // Basic IsLetter for ASCII
			contextStringBuilder.WriteRune(currentChar)
		}
		// The dead break `if (var2 != 0) { break; }` from original Java is omitted here.
		// `var2` (from hpo.b()) is 0, so `0 != 0` is false, making the break unreachable.
	}

	extractedContextString := strings.ToLower(contextStringBuilder.String())

	if !strings.HasSuffix(extractedContextString, "documentlocation") &&
		!strings.HasSuffix(extractedContextString, "documenturl") &&
		!strings.HasSuffix(extractedContextString, "windowopen") &&
		!strings.HasSuffix(extractedContextString, "windownavigate") &&
		!strings.HasSuffix(extractedContextString, "locationhref") {
		return nil
	} else {
		// return new dw9((byte)3, this.b, this.a.f, this.a.c, var5);
		// this.b is JsContextValueVal
		// this.a.f is HpoVal.ReflectionStartInInput
		// this.a.c is HpoVal.ReflectionEndInInput
		// var5 is sourceBytes
		return NewRedirectDetails(
			RedirectTypeJavaScript, // type
			reflection.jsValue,
			reflection.coreInfo.startIndexInInput,
			reflection.coreInfo.endIndexInInput,
			responseContentBytes, // The full sourceBytes, not just the scanned part for contextString
		)
	}
}
