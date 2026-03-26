package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// EncodedJavaScriptSchemeCompositeStrategy implements the ContextualXSSTechnique interface.
type EncodedJavaScriptSchemeCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator
}

// NewEncodedJavaScriptSchemeCompositeStrategy creates a new instance.
func NewEncodedJavaScriptSchemeCompositeStrategy(
	randomProvider *utils.RandomGenerator,
) *EncodedJavaScriptSchemeCompositeStrategy {
	return &EncodedJavaScriptSchemeCompositeStrategy{
		combinedStrategy: NewFirstSuccessMetaStrategy(
			NewMultiSchemeURLCompositeStrategy(randomProvider),
			NewURLProtocolRelativeCompositeStrategy(),
			NewHTMLEncodedJavaScriptSchemeStrategy(),
		),
	}
}

func (receiver *EncodedJavaScriptSchemeCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	coreReflectionInfo := reflection.CoreInfo()

	if coreReflectionInfo.GetStartIndex() != coreReflectionInfo.GetEndIndex() {
		return nil
	}

	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
