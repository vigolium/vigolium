package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeWithNewlineCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: ew8
type SchemeWithNewlineCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewSchemeWithNewlineCompositeStrategy creates a new instance of Ew8.
// Original Java constructor: public ew8(dir var1)
func NewSchemeWithNewlineCompositeStrategy(
	scheme SchemeDefinition,
) *SchemeWithNewlineCompositeStrategy {
	// Original Java logic: this.a = new c0b(new cy_(var1, "//\n"), new gfw(new nm(var1, "//\n"), new dtt()));

	// new cy_(var1, "//\n")
	schemeRandomStrategy := NewSchemeWithRandomStringStrategy(
		scheme,
		"//\n",
	) // NewCy_ is ported and returns *Cy_ which should implement ContextualXSSTechnique

	// new nm(var1, "//\n")
	schemePocRandomStrategy := NewSchemeWithPocAndRandomStringStrategy(
		scheme,
		"//\n",
	) // NewNm is a stub returning ContextualXSSTechnique

	// new dtt()
	htmlEncodedSchemeStrategy := NewHTMLEncodedJavaScriptSchemeStrategy() // NewDtt is ported and returns *Dtt which should implement ContextualXSSTechnique

	// new gfw(nmInstance, dttInstance)
	iteratorStrategy := NewFirstSuccessMetaStrategy(
		schemePocRandomStrategy,
		htmlEncodedSchemeStrategy,
	) // NewGfw is a stub returning ContextualXSSTechnique

	// new c0b(cyInstance, gfwInstance)
	finalCombinedStrategy := NewSequentialMetaStrategy(
		schemeRandomStrategy,
		iteratorStrategy,
	) // NewC0b is ported and returns *C0b which implements ContextualXSSTechnique

	return &SchemeWithNewlineCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Ew8.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *SchemeWithNewlineCompositeStrategy) GeneratePayload(
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
