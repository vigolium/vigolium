package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptInEventHandlerStrategy implements the ContextualXSSTechnique interface.
// Original Java class: deh
type JavaScriptInEventHandlerStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewJavaScriptInEventHandlerStrategy creates a new concrete instance of Deh.
// Original Java constructor: public deh(def var1, String var2)
func NewJavaScriptInEventHandlerStrategy(
	contentType *ContentTypeProfile,
	quoteChar string,
) *JavaScriptInEventHandlerStrategy {
	// Original Java logic: this.a = new gfw(new at6(var1), new dp2(var2));
	smartQuoteHandlerStrategy := NewJavaScriptSmartQuoteHandlerStrategy(contentType)
	attributeBreakoutStrategy := NewQuotedAttributeBreakoutStrategy(quoteChar)
	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		smartQuoteHandlerStrategy,
		attributeBreakoutStrategy,
	)

	return &JavaScriptInEventHandlerStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Deh.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JavaScriptInEventHandlerStrategy) GeneratePayload(
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
