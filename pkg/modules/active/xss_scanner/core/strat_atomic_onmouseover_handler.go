package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// OnmouseoverEventHandlerStrategy implements the ContextualXSSTechnique interface.
// Original Java class: f00
type OnmouseoverEventHandlerStrategy struct {
	eventValidator          *EventHandlerEligibilityLogic    // Corresponds to 'private final g1r c;'
	targetTagNames          map[string]struct{}              // Corresponds to 'private final Set<String> b;'
	combinedPayloadStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewOnmouseoverEventHandlerStrategy creates a new instance of F00.
// Original Java constructor: f00(g1r var1, Set<String> var2, String var3, String var4, String var5, String var6, boolean var7)
func NewOnmouseoverEventHandlerStrategy(
	validator *EventHandlerEligibilityLogic,
	targetTags map[string]struct{},
	prefix, randomComponent, attributeSpacing, quoteChar string,
	reflectionIsPresent bool,
) *OnmouseoverEventHandlerStrategy {
	// this.c = var1;
	// this.b = var2;
	// this.a = new c0b(new b17(var3, var4, var5, var6, var7), new flb(var3, var4, var5, var6, var7));

	basicOnmouseoverStrategy := NewBasicOnmouseoverStrategy(
		prefix,
		randomComponent,
		attributeSpacing,
		quoteChar,
		reflectionIsPresent,
	) // NewB17 returns *B17 which should implement ContextualXSSTechnique
	styledOnmouseoverStrategy := NewStyledOnmouseoverStrategy(
		prefix,
		randomComponent,
		attributeSpacing,
		quoteChar,
		reflectionIsPresent,
	) // NewFlb is a stub returning ContextualXSSTechnique
	sequentialStrategy := NewSequentialMetaStrategy(
		basicOnmouseoverStrategy,
		styledOnmouseoverStrategy,
	) // NewC0b is ported

	return &OnmouseoverEventHandlerStrategy{
		eventValidator:          validator,
		targetTagNames:          targetTags,
		combinedPayloadStrategy: sequentialStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class F00.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *OnmouseoverEventHandlerStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return !this.c.a(this.b, "onmouseover") ? null : this.a.a(var1, var2, var3, var4, var5, var6);

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
