package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeSpecificPayloadCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: es0
type SchemeSpecificPayloadCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewSchemeSpecificPayloadCompositeStrategy creates a new instance of Es0.
// Original Java constructor: public es0(dir var1)
func NewSchemeSpecificPayloadCompositeStrategy(
	scheme SchemeDefinition,
) *SchemeSpecificPayloadCompositeStrategy {
	// Original Java logic: this.a = new c0b(new cy_(var1, ""), new nm(var1, ""));

	// new cy_(var1, "") -> NewCy_(dirVar1, "") which returns *Cy_
	// *Cy_ should implement ContextualXSSTechnique
	schemeRandomStrategy := NewSchemeWithRandomStringStrategy(scheme, "")

	// new nm(var1, "") -> NewNm(dirVar1, "") which is a stub returning ContextualXSSTechnique
	schemePocRandomStrategy := NewSchemeWithPocAndRandomStringStrategy(scheme, "")

	// NewC0b is the ported constructor from c0b.go
	finalCombinedStrategy := NewSequentialMetaStrategy(schemeRandomStrategy, schemePocRandomStrategy)

	return &SchemeSpecificPayloadCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Es0.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *SchemeSpecificPayloadCompositeStrategy) GeneratePayload(
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
