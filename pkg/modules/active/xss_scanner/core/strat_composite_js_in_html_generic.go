package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JSInHTMLGenericCompositeStrategy implements the ContextualXSSTechnique interface.
type JSInHTMLGenericCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewJSInHTMLGenericCompositeStrategy creates a new instance.
func NewJSInHTMLGenericCompositeStrategy(
	contentType *ContentTypeProfile,
) *JSInHTMLGenericCompositeStrategy {
	return &JSInHTMLGenericCompositeStrategy{
		combinedStrategy: NewFirstSuccessMetaStrategy(
			NewJavaScriptSmartQuoteHandlerStrategy(contentType),
			NewTagAttributeUnquotedCompositeStrategy(),
		),
	}
}

func (receiver *JSInHTMLGenericCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
