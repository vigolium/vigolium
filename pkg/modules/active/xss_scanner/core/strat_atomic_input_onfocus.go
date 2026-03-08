package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// InputOnfocusStrategy implements the ContextualXSSTechnique interface.
// Original Java class: x2
type InputOnfocusStrategy struct {
	targetTagNames          map[string]struct{}              // Corresponds to 'private final Set<String> b;'
	combinedPayloadStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewInputOnfocusStrategy creates a new instance of X2.
// Original Java constructor: x2(Set<String> var1, String var2, String var3, String var4, String var5, boolean var6)
func NewInputOnfocusStrategy(
	targetTags map[string]struct{},
	prefix, rndComp1, attrSpacingTagEnd, quote string,
	advancedMode bool,
) *InputOnfocusStrategy {
	// this.b = var1;
	// this.a = new c0b(new ec1(var2, var3, var4, var5, var6), new ga_(var2, var3, var4, var5, var6));

	onfocusStrategy := NewOnfocusEventHandlerStrategy(
		prefix,
		rndComp1,
		attrSpacingTagEnd,
		quote,
		advancedMode,
	) // Ported
	onfocusAutofocusStrategy := NewOnfocusAutofocusStrategy(
		prefix,
		rndComp1,
		attrSpacingTagEnd,
		quote,
		advancedMode,
	) // Ported (ga_ -> Ga)
	sequentialStrategy := NewSequentialMetaStrategy(
		onfocusStrategy,
		onfocusAutofocusStrategy,
	) // Ported

	return &InputOnfocusStrategy{
		targetTagNames:          targetTags,
		combinedPayloadStrategy: sequentialStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class X2.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *InputOnfocusStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return !this.b.contains("input") ? null : this.a.a(var1, var2, var3, var4, var5, var6);

	// !this.b.contains("input")
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
