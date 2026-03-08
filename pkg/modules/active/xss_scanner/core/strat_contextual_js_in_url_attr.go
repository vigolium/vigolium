package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptInURLAttributeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: de
type JavaScriptInURLAttributeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewJavaScriptInURLAttributeStrategy creates a new concrete instance of De.
// Original Java constructor: public de(net.portswigger.ou var1, def var2, String var3)
func NewJavaScriptInURLAttributeStrategy(
	randomProvider *utils.RandomGenerator,
	contentType *ContentTypeProfile,
	quoteChar string,
) *JavaScriptInURLAttributeStrategy {
	// Original Java logic: this.a = new gfw(new dfs(var1, var2), new dp2(var3));
	jsSchemeStrategy := NewJavaScriptSchemeCompositeStrategy(randomProvider, contentType)
	attributeBreakoutStrategy := NewQuotedAttributeBreakoutStrategy(quoteChar)
	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		jsSchemeStrategy,
		attributeBreakoutStrategy,
	)

	return &JavaScriptInURLAttributeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class De.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JavaScriptInURLAttributeStrategy) GeneratePayload(
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
