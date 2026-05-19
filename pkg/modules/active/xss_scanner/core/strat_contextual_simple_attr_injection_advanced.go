package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// AdvancedQuotedSimpleAttributeInjectionStrategy implements the ContextualXSSTechnique interface.
type AdvancedQuotedSimpleAttributeInjectionStrategy struct {
	quoteChar string
}

// NewAdvancedQuotedSimpleAttributeInjectionStrategy creates a new instance.
func NewAdvancedQuotedSimpleAttributeInjectionStrategy(
	quoteChar string,
) *AdvancedQuotedSimpleAttributeInjectionStrategy {
	return &AdvancedQuotedSimpleAttributeInjectionStrategy{
		quoteChar: quoteChar,
	}
}

func (strategy *AdvancedQuotedSimpleAttributeInjectionStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := "#{random_string_5}" + strategy.quoteChar + " a=b#{random_string_5b}"
	finalProfile := profile.WithAdvancedMode(true)
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
