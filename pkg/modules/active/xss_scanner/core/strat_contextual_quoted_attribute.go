package core

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// QuotedAttributeContextStrategy implements the ContextualXSSTechnique interface.
type QuotedAttributeContextStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewQuotedAttributeContextStrategy creates a new instance.
func NewQuotedAttributeContextStrategy(quoteByte byte) *QuotedAttributeContextStrategy {
	receiver := &QuotedAttributeContextStrategy{}

	quotedPayloadStrategy := receiver.createPayloadStrategyForQuote(
		rune(quoteByte),
	) // Convert byte to rune for char type

	charInjectionStrategy := NewSingleCharacterInjectionStrategy(quoteByte)

	finalCombinedStrategy := NewSequentialMetaStrategy(
		quotedPayloadStrategy,
		charInjectionStrategy,
	)
	receiver.combinedStrategy = finalCombinedStrategy

	return receiver
}

func (strategy *QuotedAttributeContextStrategy) GeneratePayload(
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

func (strategy *QuotedAttributeContextStrategy) createPayloadStrategyForQuote(
	quoteChar rune,
) ContextualAttackPayloadGenerator {
	return &quotedAttributeLambdaWrapper{capturedQuoteChar: quoteChar}
}

func createQuotedAttributePayload(
	quoteChar rune,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	quoteCharStr := string(quoteChar)
	formattedPayload := fmt.Sprintf(
		"%s#{random_string_5}%sa=b#{random_string_5b}",
		quoteCharStr,
		quoteCharStr,
	)

	return probeBuilder.WithoutSecondaryCanary().BuildFinding(byte(2), formattedPayload, profile)
}

// quotedAttributeLambdaWrapper implements ContextualXSSTechnique and captures the character for the lambda.
type quotedAttributeLambdaWrapper struct {
	capturedQuoteChar rune
}

func (w *quotedAttributeLambdaWrapper) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return createQuotedAttributePayload(
		w.capturedQuoteChar,
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
