package core

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// XMLNamespaceOnloadStrategy implements the ContextualXSSTechnique interface.
// Original Java class: exb
type XMLNamespaceOnloadStrategy struct {
	payloadGeneratingStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique b;'
	contentTypeProfile        *ContentTypeProfile              // Corresponds to 'private final def a;'
}

// createXMLNamespaceOnloadPayload corresponds to the static Java lambda lambda$new$0
// Original signature: private static PreliminaryXSSFinding lambda$new$0(String var0, char[] var1, int var2, boolean var3, hgm var4, hnx var5, byte var6, byte var7, DetectedReflection var8, byte[] var9)
func createXMLNamespaceOnloadPayload(
	prefix string,
	quoteChar rune,
	useAdvancedMode bool,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	byteVal6 ReflectionTacticType,
	byteVal7 ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	bytesVal9 *utils.HTTPTransaction,
) PotentialXSSFinding {

	// String.format("%s<a xmlns:a=%shttp://www.w3.org/1999/xhtml%s><a:body onload=%s%s%s/></a>",
	//    var0_cap_str, var1_cap_char_array[var2_cap_idx], ... )
	// In Go, var1_cap_char_array[var2_cap_idx] is directly var1CapChar (the rune)
	xmlPayloadBody := fmt.Sprintf(
		"%s<a xmlns:a=%shttp://www.w3.org/1999/xhtml%s><a:body onload=%s%s%s/></a>",
		prefix,
		string(quoteChar),
		string(quoteChar),
		string(quoteChar),
		"#{poc}",
		string(quoteChar),
	)

	finalFormattedPayload := "#{random_string_5}" + xmlPayloadBody + "#{random_string_5b}"

	// var5_arg_hnx.a(var3_cap_bool) now returns Hnx
	finalProfile := profile.WithAdvancedMode(useAdvancedMode)
	return probeBuilder.WithAdditionalScanFlags(4).
		BuildFinding(byte(12), finalFormattedPayload, finalProfile)
}

// xmlNamespaceOnloadLambdaWrapper implements ContextualXSSTechnique and captures variables for lambdaNew0Exb.
type xmlNamespaceOnloadLambdaWrapper struct {
	capturedPrefix          string
	capturedQuoteChar       rune
	capturedUseAdvancedMode bool
}

func (w *xmlNamespaceOnloadLambdaWrapper) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Pass captured values and ContextualXSSTechnique.A arguments to the static lambda logic
	return createXMLNamespaceOnloadPayload(
		w.capturedPrefix,
		w.capturedQuoteChar,
		w.capturedUseAdvancedMode,
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}

// NewXMLNamespaceOnloadStrategy creates a new instance of Exb.
// Original Java constructor: public exb(def var1, String var2, boolean var3)
func NewXMLNamespaceOnloadStrategy(
	contentType *ContentTypeProfile,
	prefix string,
	useAdvancedMode bool,
) *XMLNamespaceOnloadStrategy {
	receiver := &XMLNamespaceOnloadStrategy{contentTypeProfile: contentType}

	// char[] var5 = new char[]{'\'', '\"'}; // char array of quote and double quote
	quoteCharsToTry := []rune{'\'', '"'}

	// ContextualXSSTechnique[] var6 = new ContextualXSSTechnique[var5.length]; // Array of ContextualXSSTechnique, size 2
	strategiesForQuotes := make([]ContextualAttackPayloadGenerator, len(quoteCharsToTry))

	// int var7 = 0;
	// while (var7 < var5.length) { ... }
	for index := 0; index < len(quoteCharsToTry); index++ {
		// var6[var7] = exb::lambda$new$0;
		// Create a wrapper instance that captures the necessary variables.
		strategiesForQuotes[index] = &xmlNamespaceOnloadLambdaWrapper{
			capturedPrefix:          prefix,
			capturedQuoteChar:       quoteCharsToTry[index],
			capturedUseAdvancedMode: useAdvancedMode,
		}

	}

	// this.b = new gfw(var6);
	receiver.payloadGeneratingStrategy = NewFirstSuccessMetaStrategy(strategiesForQuotes...)

	return receiver
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Exb.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *XMLNamespaceOnloadStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// return this.a.e != 262 ? null : this.b.a(var1, var2, var3, var4, var5, var6);
	// this.a is 'def'. this.a.e is def.e (short)
	// 262 is DefTypeXML (constant from stubs.go)
	if receiver.contentTypeProfile == nil || receiver.contentTypeProfile.GetStatedTypeCode() != DefTypeXML {
		return nil
	}
	return receiver.payloadGeneratingStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
