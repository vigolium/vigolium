package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// QuotedSimpleAttributeInjectionStrategy implements the ContextualXSSTechnique interface.
type QuotedSimpleAttributeInjectionStrategy struct {
	quoteChar string
}

// NewQuotedSimpleAttributeInjectionStrategy creates a new instance.
func NewQuotedSimpleAttributeInjectionStrategy(
	quoteChar string,
) *QuotedSimpleAttributeInjectionStrategy {
	return &QuotedSimpleAttributeInjectionStrategy{
		quoteChar: quoteChar,
	}
}

func (strategy *QuotedSimpleAttributeInjectionStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := "#{random_string_5}" + strategy.quoteChar + "a=" + strategy.quoteChar + "b" + strategy.quoteChar + "#{random_string_5b}"

	return probeBuilder.WithoutSecondaryCanary().BuildFinding(byte(2), formattedPayload, profile)
}
