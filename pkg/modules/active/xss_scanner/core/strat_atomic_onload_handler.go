package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// OnloadEventHandlerStrategy implements the ContextualXSSTechnique interface.
// Original Java class: b8
type OnloadEventHandlerStrategy struct {
	eventValidator            *EventHandlerEligibilityLogic // Corresponds to 'c' (g1r) in Java
	targetTagNames            map[string]struct{}           // Corresponds to 'e' (Set<String>) in Java. Using map for Set behavior.
	prefix                    string                        // Corresponds to 'a' (String) in Java
	randomComponent1          string                        // Corresponds to 'd' (String) in Java
	attributeSpacingAndTagEnd string                        // Corresponds to 'g' (String) in Java
	quoteChar                 string                        // Corresponds to 'b' (String) in Java
	useAdvancedMode           bool                          // Corresponds to 'f' (boolean) in Java
}

// NewOnloadEventHandlerStrategy creates a new instance of B8.
// Original Java constructor: public b8(g1r var1, Set<String> var2, String var3, String var4, String var5, String var6, boolean var7)
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

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *OnloadEventHandlerStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return !this.c.a(this.e, "onload")
	//    ? null
	//    : var1.a(20)
	//       .a(
	//          (byte)2,
	//          this.a + "#{random_string_5}" + this.d + this.g + "onload=" + this.b + "#{poc}" + this.b + this.g + "#{random_string_5b}",
	//          var2.a(new bg8(var4, "onload")).a(this.f)
	//       );

	// Ported condition: !this.c.a(this.e, "onload")
	// receiver.ValG1r.A(receiver.ValSetE, "onload")
	if !receiver.eventValidator.AreTagsEligibleForEvent(receiver.targetTagNames, "onload") {
		return nil
	}

	// Payload string construction
	formattedPayload := receiver.prefix + "#{random_string_5}" + receiver.randomComponent1 + receiver.attributeSpacingAndTagEnd +
		"onload=" + receiver.quoteChar + "#{poc}" + receiver.quoteChar + receiver.attributeSpacingAndTagEnd +
		"#{random_string_5b}"

	// Hnx methods now return Hnx for chaining.
	finalProfile := profile.WithAdditionalMatchCriterion(NewAttributeValueEventMatcher(contextType, "onload")).
		WithAdvancedMode(receiver.useAdvancedMode)

	// Call BuildBgf on Hgm
	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
