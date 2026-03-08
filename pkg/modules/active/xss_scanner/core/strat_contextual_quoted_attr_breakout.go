package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// QuotedAttributeBreakoutStrategy implements the ContextualXSSTechnique interface.
// Original Java class: dp2
type QuotedAttributeBreakoutStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewQuotedAttributeBreakoutStrategy creates a new instance of Dp2.
// Original Java constructor: public dp2(String var1)
func NewQuotedAttributeBreakoutStrategy(quoteChar string) *QuotedAttributeBreakoutStrategy {
	// Original Java logic:
	// this.a = new gfw(
	//    new epq(var1 + ">", true),
	//    new c0b(new hps(var1), new fi0("", var1, "", var1, false)),
	//    new c0b(new fgz(var1), new fi0("", var1, " ", "", true))
	// );

	tagBreakoutWithQuoteStrategy := NewGenericBreakoutCompositeStrategy(
		quoteChar+">",
		true,
	) // NewEpq stub returns ContextualXSSTechnique

	simpleInjectionStrategy := NewQuotedSimpleAttributeInjectionStrategy(
		quoteChar,
	) // NewHps stub returns ContextualXSSTechnique
	eventHandlerStrategy1 := NewAttributeEventHandlerCompositeStrategy(
		"",
		quoteChar,
		"",
		quoteChar,
		false,
	) // NewFi0 stub returns Fi0, but c0b needs ContextualXSSTechnique
	// Assuming NewFi0 actually returns a ContextualXSSTechnique implementer, or we need a Fi0->ContextualXSSTechnique adapter if fi0 itself is ContextualXSSTechnique
	// From fi0.java: class fi0 implements ContextualXSSTechnique.
	// Let's adjust NewFi0 stub if necessary, or assume it's fine for now.
	sequence1 := NewSequentialMetaStrategy(
		simpleInjectionStrategy,
		eventHandlerStrategy1,
	) // NewC0b is the actual ported constructor from c0b.go

	advancedInjectionStrategy := NewAdvancedQuotedSimpleAttributeInjectionStrategy(
		quoteChar,
	) // NewFgz stub returns ContextualXSSTechnique
	eventHandlerStrategy2 := NewAttributeEventHandlerCompositeStrategy("", quoteChar, " ", "", true)
	sequence2 := NewSequentialMetaStrategy(advancedInjectionStrategy, eventHandlerStrategy2)

	finalIteratorStrategy := NewFirstSuccessMetaStrategy(
		tagBreakoutWithQuoteStrategy,
		sequence1,
		sequence2,
	) // NewGfw stub returns ContextualXSSTechnique

	return &QuotedAttributeBreakoutStrategy{
		combinedStrategy: finalIteratorStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Dp2.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (strategy *QuotedAttributeBreakoutStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return this.a.a(var1, var2, var3, var4, var5, var6);
	return strategy.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
