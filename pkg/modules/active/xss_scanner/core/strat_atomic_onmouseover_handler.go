package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// OnmouseoverEventHandlerStrategy implements the ContextualXSSTechnique interface.
type OnmouseoverEventHandlerStrategy struct {
	eventValidator          *EventHandlerEligibilityLogic
	targetTagNames          map[string]struct{}
	combinedPayloadStrategy ContextualAttackPayloadGenerator
}

// NewOnmouseoverEventHandlerStrategy creates a new instance.
func NewOnmouseoverEventHandlerStrategy(
	validator *EventHandlerEligibilityLogic,
	targetTags map[string]struct{},
	prefix, randomComponent, attributeSpacing, quoteChar string,
	reflectionIsPresent bool,
) *OnmouseoverEventHandlerStrategy {

	basicOnmouseoverStrategy := NewBasicOnmouseoverStrategy(
		prefix,
		randomComponent,
		attributeSpacing,
		quoteChar,
		reflectionIsPresent,
	)
	styledOnmouseoverStrategy := NewStyledOnmouseoverStrategy(
		prefix,
		randomComponent,
		attributeSpacing,
		quoteChar,
		reflectionIsPresent,
	)
	sequentialStrategy := NewSequentialMetaStrategy(
		basicOnmouseoverStrategy,
		styledOnmouseoverStrategy,
	)

	return &OnmouseoverEventHandlerStrategy{
		eventValidator:          validator,
		targetTagNames:          targetTags,
		combinedPayloadStrategy: sequentialStrategy,
	}
}

func (receiver *OnmouseoverEventHandlerStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	if !receiver.eventValidator.AreTagsEligibleForEvent(receiver.targetTagNames, "onmouseover") {
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
