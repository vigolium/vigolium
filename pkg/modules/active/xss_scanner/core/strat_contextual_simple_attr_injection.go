package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// QuotedSimpleAttributeInjectionStrategy implements the ContextualXSSTechnique interface.
// Original Java class: hps
type QuotedSimpleAttributeInjectionStrategy struct {
	quoteChar string // Corresponds to 'a' in Java
}

// NewQuotedSimpleAttributeInjectionStrategy creates a new instance of Hps.
// Original Java constructor: public hps(String var1)
func NewQuotedSimpleAttributeInjectionStrategy(
	quoteChar string,
) *QuotedSimpleAttributeInjectionStrategy {
	return &QuotedSimpleAttributeInjectionStrategy{
		quoteChar: quoteChar,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (strategy *QuotedSimpleAttributeInjectionStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// String var7 = "#{random_string_5}" + this.a + "a=" + this.a + "b" + this.a + "#{random_string_5b}";
	// return var1.c().a((byte)2, var7, var2);

	formattedPayload := "#{random_string_5}" + strategy.quoteChar + "a=" + strategy.quoteChar + "b" + strategy.quoteChar + "#{random_string_5b}"

	return probeBuilder.WithoutSecondaryCanary().BuildFinding(byte(2), formattedPayload, profile)
}
