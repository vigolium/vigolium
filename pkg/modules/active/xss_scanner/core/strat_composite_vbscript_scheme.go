package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// VBScriptSchemeCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: gg9
type VBScriptSchemeCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewVBScriptSchemeCompositeStrategy creates a new instance of Gg9.
// Original Java constructor: public gg9(dir var1)
func NewVBScriptSchemeCompositeStrategy(dirVar1 SchemeDefinition) *VBScriptSchemeCompositeStrategy {
	// Original Java logic: this.a = new c0b(new c8g(var1), new gdz(var1));

	schemeRandomAdvancedStrategy := NewSchemeWithRandomStringAdvancedStrategy(dirVar1)                     // Ported
	schemeMsgboxStrategy := NewSchemeMsgboxPayloadStrategy(dirVar1)                                        // Ported
	finalCombinedStrategy := NewSequentialMetaStrategy(schemeRandomAdvancedStrategy, schemeMsgboxStrategy) // Ported

	return &VBScriptSchemeCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Gg9.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *VBScriptSchemeCompositeStrategy) GeneratePayload(
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
