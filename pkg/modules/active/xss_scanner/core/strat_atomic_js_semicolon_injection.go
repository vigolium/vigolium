package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptSemicolonInjectionStrategy implements the ContextualXSSTechnique interface.
type JavaScriptSemicolonInjectionStrategy struct {
	delegateStrategy ContextualAttackPayloadGenerator
}

// NewJavaScriptSemicolonInjectionStrategy creates a new instance.
func NewJavaScriptSemicolonInjectionStrategy(
	params JavaScriptPayloadParams,
	useHTMLEntityVariants bool,
) *JavaScriptSemicolonInjectionStrategy {

	numericStringVariantStrategy := NewJSNumericStringVariantCompositeStrategy(
		params.primaryComponent+";",
		params.encodedComponent+";",
		useHTMLEntityVariants,
	)

	return &JavaScriptSemicolonInjectionStrategy{
		delegateStrategy: numericStringVariantStrategy,
	}
}

func (receiver *JavaScriptSemicolonInjectionStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return receiver.delegateStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
