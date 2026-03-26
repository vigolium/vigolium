package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JSStringSemicolonVariantStrategy implements the ContextualXSSTechnique interface.
type JSStringSemicolonVariantStrategy struct {
	delegateStrategy ContextualAttackPayloadGenerator
}

// NewJSStringSemicolonVariantStrategy creates a new instance.
func NewJSStringSemicolonVariantStrategy(
	baseParams JavaScriptPayloadParams,
	useHTMLEntityVariants bool,
) *JSStringSemicolonVariantStrategy {

	paramsWithSemicolon := JavaScriptPayloadParams{
		primaryComponent: baseParams.primaryComponent + ";",
		encodedComponent: baseParams.encodedComponent + ";",
		flag:             baseParams.flag,
	}

	encodedVariantStrategy := NewEncodedJSStringVariantStrategy(
		paramsWithSemicolon,
		useHTMLEntityVariants,
	)

	return &JSStringSemicolonVariantStrategy{
		delegateStrategy: encodedVariantStrategy,
	}
}

func (receiver *JSStringSemicolonVariantStrategy) GeneratePayload(
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
