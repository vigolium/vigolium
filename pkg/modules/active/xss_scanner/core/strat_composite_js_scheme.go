package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptSchemeCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: dfs
type JavaScriptSchemeCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewJavaScriptSchemeCompositeStrategy creates a new instance of Dfs.
// Original Java constructor: dfs(ou var1, def var2)
func NewJavaScriptSchemeCompositeStrategy(
	randomProvider *utils.RandomGenerator,
	contentType *ContentTypeProfile,
) *JavaScriptSchemeCompositeStrategy {
	// Original Java logic: this.a = new gfw(new ao9(var1), new fcq(var2), new htc());

	// new ao9(var1) -> NewAo9(ouVar1) which returns *Ao9.
	// We need ContextualXSSTechnique. Assuming *Ao9 implements ContextualXSSTechnique.
	encodedSchemeStrategy := NewEncodedJavaScriptSchemeCompositeStrategy(
		randomProvider,
	) // Returns *Ao9, which should implement ContextualXSSTechnique
	scriptAttributeStrategy := NewScriptSchemeInAttributeStrategy(
		contentType,
	) // NewFcq is a stub returning ContextualXSSTechnique, needs to accept *Def
	vbscriptAttributeStrategy := NewVBScriptAttributeStrategy() // NewHtc is a stub returning ContextualXSSTechnique

	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		encodedSchemeStrategy,
		scriptAttributeStrategy,
		vbscriptAttributeStrategy,
	)

	return &JavaScriptSchemeCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Dfs.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JavaScriptSchemeCompositeStrategy) GeneratePayload(
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
