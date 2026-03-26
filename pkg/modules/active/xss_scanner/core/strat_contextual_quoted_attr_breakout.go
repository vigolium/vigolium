package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// QuotedAttributeBreakoutStrategy implements the ContextualXSSTechnique interface.
type QuotedAttributeBreakoutStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewQuotedAttributeBreakoutStrategy creates a new instance.
func NewQuotedAttributeBreakoutStrategy(quoteChar string) *QuotedAttributeBreakoutStrategy {

	tagBreakoutWithQuoteStrategy := NewGenericBreakoutCompositeStrategy(
		quoteChar+">",
		true,
	)

	simpleInjectionStrategy := NewQuotedSimpleAttributeInjectionStrategy(
		quoteChar,
	)
	eventHandlerStrategy1 := NewAttributeEventHandlerCompositeStrategy(
		"",
		quoteChar,
		"",
		quoteChar,
		false,
	)
	sequence1 := NewSequentialMetaStrategy(
		simpleInjectionStrategy,
		eventHandlerStrategy1,
	)
	advancedInjectionStrategy := NewAdvancedQuotedSimpleAttributeInjectionStrategy(
		quoteChar,
	)
	eventHandlerStrategy2 := NewAttributeEventHandlerCompositeStrategy("", quoteChar, " ", "", true)
	sequence2 := NewSequentialMetaStrategy(advancedInjectionStrategy, eventHandlerStrategy2)

	finalIteratorStrategy := NewFirstSuccessMetaStrategy(
		tagBreakoutWithQuoteStrategy,
		sequence1,
		sequence2,
	)

	return &QuotedAttributeBreakoutStrategy{
		combinedStrategy: finalIteratorStrategy,
	}
}

func (strategy *QuotedAttributeBreakoutStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return strategy.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
