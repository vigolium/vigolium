package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ConditionalScriptTagCheckMetaStrategy implements the ContextualXSSTechnique interface.
type ConditionalScriptTagCheckMetaStrategy struct {
	delegateStrategy   ContextualAttackPayloadGenerator
	contentTypeProfile *ContentTypeProfile
	skipIfScript       bool
}

// NewConditionalScriptTagCheckMetaStrategy creates a new instance.
func NewConditionalScriptTagCheckMetaStrategy(
	contentType *ContentTypeProfile,
	skipIfScript bool,
) *ConditionalScriptTagCheckMetaStrategy {
	tagBreakoutStrategy := NewSpecificTagBreakoutCompositeStrategy(
		"script",
		byte(5),
	)

	return &ConditionalScriptTagCheckMetaStrategy{
		delegateStrategy:   tagBreakoutStrategy,
		contentTypeProfile: contentType,
		skipIfScript:       skipIfScript,
	}
}

func (strategy *ConditionalScriptTagCheckMetaStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	if strategy.contentTypeProfile != nil && !strategy.skipIfScript &&
		strategy.contentTypeProfile.GetInferredTypeCode() != DefTypeScript {
		return strategy.delegateStrategy.GeneratePayload(
			probeBuilder,
			profile,
			tactic,
			contextType,
			reflection,
			transaction,
		)
	}
	return nil
}
