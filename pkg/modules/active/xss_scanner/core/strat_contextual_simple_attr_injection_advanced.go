package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// AdvancedQuotedSimpleAttributeInjectionStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fgz
type AdvancedQuotedSimpleAttributeInjectionStrategy struct {
	quoteChar string // Corresponds to 'a' in Java
}

// NewAdvancedQuotedSimpleAttributeInjectionStrategy creates a new instance of Fgz.
// Original Java constructor: public fgz(String var1)
func NewAdvancedQuotedSimpleAttributeInjectionStrategy(
	quoteChar string,
) *AdvancedQuotedSimpleAttributeInjectionStrategy {
	return &AdvancedQuotedSimpleAttributeInjectionStrategy{
		quoteChar: quoteChar,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (strategy *AdvancedQuotedSimpleAttributeInjectionStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var1.c().a((byte)2, "#{random_string_5}" + this.a + " a=b#{random_string_5b}", var2.a(true));
	formattedPayload := "#{random_string_5}" + strategy.quoteChar + " a=b#{random_string_5b}"
	finalProfile := profile.WithAdvancedMode(true)
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
