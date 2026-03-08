package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// XMLHTMLGenericCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fe2
type XMLHTMLGenericCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewXMLHTMLGenericCompositeStrategy creates a new instance of Fe2.
// Original Java constructor: public fe2(String var1, boolean var2, def var3)
func NewXMLHTMLGenericCompositeStrategy(
	prefix string,
	useAdvancedMode bool,
	contentType *ContentTypeProfile,
) *XMLHTMLGenericCompositeStrategy {
	// Original Java logic: this.a = new c0b(new fa9(var1, var2), new exb(var3, var1, var2));

	// new fa9(var1, var2) -> NewFa9(strVar1, boolVar2) which returns *Fa9 (should implement ContextualXSSTechnique)
	genericXSSStrategy := NewGenericXSSCompositeStrategy(prefix, useAdvancedMode)

	// new exb(var3, var1, var2) -> NewExb(defVar3, strVar1, boolVar2) which returns *Exb (should implement ContextualXSSTechnique)
	xmlNamespaceStrategy := NewXMLNamespaceOnloadStrategy(contentType, prefix, useAdvancedMode)

	// NewC0b is the ported constructor from c0b.go
	finalCombinedStrategy := NewSequentialMetaStrategy(genericXSSStrategy, xmlNamespaceStrategy)

	return &XMLHTMLGenericCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Fe2.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *XMLHTMLGenericCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return this.a.a(var1, var2, var3, var4, var5, var6);
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
