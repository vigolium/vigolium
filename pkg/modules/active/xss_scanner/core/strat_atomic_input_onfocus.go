package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// InputOnfocusStrategy implements the ContextualXSSTechnique interface.
type InputOnfocusStrategy struct {
	targetTagNames          map[string]struct{}
	combinedPayloadStrategy ContextualAttackPayloadGenerator
}

// NewInputOnfocusStrategy creates a new instance.
func NewInputOnfocusStrategy(
	targetTags map[string]struct{},
	prefix, rndComp1, attrSpacingTagEnd, quote string,
	advancedMode bool,
) *InputOnfocusStrategy {

	onfocusStrategy := NewOnfocusEventHandlerStrategy(
		prefix,
		rndComp1,
		attrSpacingTagEnd,
		quote,
		advancedMode,
	)
	onfocusAutofocusStrategy := NewOnfocusAutofocusStrategy(
		prefix,
		rndComp1,
		attrSpacingTagEnd,
		quote,
		advancedMode,
	)
	sequentialStrategy := NewSequentialMetaStrategy(
		onfocusStrategy,
		onfocusAutofocusStrategy,
	)
	return &InputOnfocusStrategy{
		targetTagNames:          targetTags,
		combinedPayloadStrategy: sequentialStrategy,
	}
}

func (receiver *InputOnfocusStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	if _, ok := receiver.targetTagNames["input"]; !ok {
		return nil
	}
	return receiver.combinedPayloadStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
