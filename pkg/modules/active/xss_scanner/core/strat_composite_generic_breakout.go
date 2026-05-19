package core

import (
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// GenericBreakoutCompositeStrategy implements the ContextualXSSTechnique interface.
type GenericBreakoutCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewGenericBreakoutCompositeStrategy creates a new instance.
func NewGenericBreakoutCompositeStrategy(
	prefix string,
	useAdvancedMode bool,
) *GenericBreakoutCompositeStrategy {
	zap.L().Debug("[GenericBreakout] creating strategy",
		zap.String("prefix", prefix),
		zap.Bool("useAdvancedMode", useAdvancedMode))
	finalCombinedStrategy := NewSequentialMetaStrategy(
		NewGenericXSSCompositeStrategy(prefix, useAdvancedMode),
		NewFirstSuccessMetaStrategy(
			NewBasicScriptTagStrategy(prefix, useAdvancedMode),
			NewCaseVariantScriptTagStrategy(prefix, useAdvancedMode),
			NewSequentialMetaStrategy(
				NewSimpleAnchorAttributeStrategy(prefix, useAdvancedMode),
				NewFirstSuccessMetaStrategy(
					NewImageOnErrorStrategy(prefix, useAdvancedMode),
					NewInputAutofocusOnfocusStrategy(prefix, useAdvancedMode),
				),
			),
		),
	)

	instance := &GenericBreakoutCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}

	return instance
}

func (receiver *GenericBreakoutCompositeStrategy) GeneratePayload(
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
