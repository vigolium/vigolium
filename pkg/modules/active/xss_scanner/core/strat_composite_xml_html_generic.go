package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// XMLHTMLGenericCompositeStrategy implements the ContextualXSSTechnique interface.
type XMLHTMLGenericCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewXMLHTMLGenericCompositeStrategy creates a new instance.
func NewXMLHTMLGenericCompositeStrategy(
	prefix string,
	useAdvancedMode bool,
	contentType *ContentTypeProfile,
) *XMLHTMLGenericCompositeStrategy {

	genericXSSStrategy := NewGenericXSSCompositeStrategy(prefix, useAdvancedMode)

	xmlNamespaceStrategy := NewXMLNamespaceOnloadStrategy(contentType, prefix, useAdvancedMode)

	finalCombinedStrategy := NewSequentialMetaStrategy(genericXSSStrategy, xmlNamespaceStrategy)

	return &XMLHTMLGenericCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

func (receiver *XMLHTMLGenericCompositeStrategy) GeneratePayload(
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
