package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptCommentBreakoutStrategy implements the ContextualXSSTechnique interface.
// Original Java class: hee
type JavaScriptCommentBreakoutStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewJavaScriptCommentBreakoutStrategy creates a new instance of Hee.
// Original Java constructor: public hee(String var1, def var2, boolean var3)
func NewJavaScriptCommentBreakoutStrategy(
	commentTerminator string,
	contentType *ContentTypeProfile,
	useVariants bool,
) *JavaScriptCommentBreakoutStrategy {
	// Original Java logic: this.a = new gfw(new bzp(var1, "", var3), new dw1(var2, var3));

	terminatorVariantStrategy := NewJSCommentTerminatorVariantStrategy(
		commentTerminator,
		"",
		useVariants,
	)
	scriptTagCheckStrategy := NewConditionalScriptTagCheckMetaStrategy(
		contentType,
		useVariants,
	)
	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		terminatorVariantStrategy,
		scriptTagCheckStrategy,
	)

	return &JavaScriptCommentBreakoutStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Hee.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JavaScriptCommentBreakoutStrategy) GeneratePayload(
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
