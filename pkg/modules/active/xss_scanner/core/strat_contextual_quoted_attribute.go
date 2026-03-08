package core

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// QuotedAttributeContextStrategy implements the ContextualXSSTechnique interface.
// Original Java class: gu9
type QuotedAttributeContextStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewQuotedAttributeContextStrategy creates a new instance of Gu9.
// Original Java constructor: public gu9(byte var1)
func NewQuotedAttributeContextStrategy(quoteByte byte) *QuotedAttributeContextStrategy {
	receiver := &QuotedAttributeContextStrategy{}

	// this.a = new c0b(this.a((char)var1), new d1v(var1));
	// this.a((char)var1)
	quotedPayloadStrategy := receiver.createPayloadStrategyForQuote(
		rune(quoteByte),
	) // Convert byte to rune for char type

	// new d1v(var1)
	charInjectionStrategy := NewSingleCharacterInjectionStrategy(quoteByte) // NewD1v is ported

	finalCombinedStrategy := NewSequentialMetaStrategy(
		quotedPayloadStrategy,
		charInjectionStrategy,
	) // NewC0b is ported
	receiver.combinedStrategy = finalCombinedStrategy

	return receiver
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Gu9.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
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

// createPayloadStrategyForQuote is the Go equivalent of private ContextualXSSTechnique a(char var1)
func (strategy *QuotedAttributeContextStrategy) createPayloadStrategyForQuote(
	quoteChar rune,
) ContextualAttackPayloadGenerator {
	// return gu9::lambda$createInjection$0;
	return &quotedAttributeLambdaWrapper{capturedQuoteChar: quoteChar}
}

// createQuotedAttributePayload is the Go equivalent of the static Java lambda lambda$createInjection$0
// private static PreliminaryXSSFinding lambda$createInjection$0(char var0_char_captured, hgm var1, hnx var2, ...)
func createQuotedAttributePayload(
	quoteChar rune,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// String var7 = var0_char_captured + "#{random_string_5}" + var0_char_captured + "a=b#{random_string_5b}";
	quoteCharStr := string(quoteChar)
	formattedPayload := fmt.Sprintf(
		"%s#{random_string_5}%sa=b#{random_string_5b}",
		quoteCharStr,
		quoteCharStr,
	)

	// return var1.c().a((byte)2, var7, var2);
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
