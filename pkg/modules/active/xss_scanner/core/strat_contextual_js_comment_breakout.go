package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptCommentBreakoutStrategy implements the ContextualXSSTechnique interface.
type JavaScriptCommentBreakoutStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewJavaScriptCommentBreakoutStrategy creates a new instance.
func NewJavaScriptCommentBreakoutStrategy(
	commentTerminator string,
	contentType *ContentTypeProfile,
	useVariants bool,
) *JavaScriptCommentBreakoutStrategy {

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

func (receiver *JavaScriptCommentBreakoutStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
