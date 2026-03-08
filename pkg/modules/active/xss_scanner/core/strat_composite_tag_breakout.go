package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SpecificTagBreakoutCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fo0
type SpecificTagBreakoutCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewSpecificTagBreakoutCompositeStrategy creates a new instance of Fo0.
// Original Java constructor: public fo0(String var1, byte var2)
func NewSpecificTagBreakoutCompositeStrategy(
	tagName string,
	contextCode byte,
) *SpecificTagBreakoutCompositeStrategy {
	// Original Java logic:
	// this.a = new gfw(
	//    new c0b(new eko(var1, var2), new epq("</" + var1 + ">", false)),
	//    new c0b(new iw1(var1, var2), new epq("</" + cqz.e(var1) + " >", false))
	// );

	// First c0b component
	simpleClosingTagStrategy := NewClosingTagStrategy(tagName, contextCode)
	closingTagPayload1 := "</" + tagName + ">"
	genericBreakoutStrategy1 := NewGenericBreakoutCompositeStrategy(closingTagPayload1, false)
	sequence1 := NewSequentialMetaStrategy(simpleClosingTagStrategy, genericBreakoutStrategy1)

	// Second c0b component
	processedClosingTagStrategy := NewProcessedClosingTagStrategy(tagName, contextCode)
	processedTagName := mangleTagNameForClosing(tagName)
	closingTagPayload2 := "</" + processedTagName + " >"
	genericBreakoutStrategy2 := NewGenericBreakoutCompositeStrategy(closingTagPayload2, false)
	sequence2 := NewSequentialMetaStrategy(processedClosingTagStrategy, genericBreakoutStrategy2)

	finalCombinedStrategy := NewFirstSuccessMetaStrategy(sequence1, sequence2)

	return &SpecificTagBreakoutCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Fo0.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *SpecificTagBreakoutCompositeStrategy) GeneratePayload(
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
