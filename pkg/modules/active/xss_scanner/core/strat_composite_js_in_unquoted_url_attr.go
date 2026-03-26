package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JSInUnquotedURLAttributeCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: h0i
type JSInUnquotedURLAttributeCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewJSInUnquotedURLAttributeCompositeStrategy creates a new instance of H0i.
// Original Java constructor: public h0i(ou var1, def var2)
func NewJSInUnquotedURLAttributeCompositeStrategy(
	randomProvider *utils.RandomGenerator,
	contentType *ContentTypeProfile,
) *JSInUnquotedURLAttributeCompositeStrategy {
	// Original Java logic: this.a = new gfw(new dfs(var1, var2), new h9c());

	jsSchemeCompositeStrategy := NewJavaScriptSchemeCompositeStrategy(
		randomProvider,
		contentType,
	) // NewDfs returns *Dfs (should implement ContextualXSSTechnique)
	tagAttributeUnquotedStrategy := NewTagAttributeUnquotedCompositeStrategy() // NewH9c is a stub returning ContextualXSSTechnique
	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		jsSchemeCompositeStrategy,
		tagAttributeUnquotedStrategy,
	) // NewGfw is stubbed

	return &JSInUnquotedURLAttributeCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class H0i.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JSInUnquotedURLAttributeCompositeStrategy) GeneratePayload(
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
