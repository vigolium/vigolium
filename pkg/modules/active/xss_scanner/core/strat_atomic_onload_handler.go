package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// OnloadEventHandlerStrategy implements the ContextualXSSTechnique interface.
type OnloadEventHandlerStrategy struct {
	eventValidator            *EventHandlerEligibilityLogic
	targetTagNames            map[string]struct{}
	prefix                    string
	randomComponent1          string
	attributeSpacingAndTagEnd string
	quoteChar                 string
	useAdvancedMode           bool
}

// NewOnloadEventHandlerStrategy creates a new instance.
func NewOnloadEventHandlerStrategy(
	var1 *EventHandlerEligibilityLogic,
	var2 map[string]struct{},
	var3, var4, var5, var6 string,
	var7 bool,
) *OnloadEventHandlerStrategy {
	return &OnloadEventHandlerStrategy{
		eventValidator:            var1,
		targetTagNames:            var2,
		prefix:                    var3,
		randomComponent1:          var4,
		attributeSpacingAndTagEnd: var5,
		quoteChar:                 var6,
		useAdvancedMode:           var7,
	}
}

func (receiver *OnloadEventHandlerStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	if !receiver.eventValidator.AreTagsEligibleForEvent(receiver.targetTagNames, "onload") {
		return nil
	}

	// Payload string construction
	formattedPayload := receiver.prefix + "#{random_string_5}" + receiver.randomComponent1 + receiver.attributeSpacingAndTagEnd +
		"onload=" + receiver.quoteChar + "#{poc}" + receiver.quoteChar + receiver.attributeSpacingAndTagEnd +
		"#{random_string_5b}"

	finalProfile := profile.WithAdditionalMatchCriterion(NewAttributeValueEventMatcher(contextType, "onload")).
		WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
