package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

type URLProtocolRelativeCompositeStrategy struct{}

// NewURLProtocolRelativeCompositeStrategy creates a new instance.
func NewURLProtocolRelativeCompositeStrategy() *URLProtocolRelativeCompositeStrategy {
	return &URLProtocolRelativeCompositeStrategy{}
}


func (receiver *URLProtocolRelativeCompositeStrategy) A_HgmHnx(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	formattedPayload := "#{random_string_5}://#{random_string_5b}"
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(11), formattedPayload, profile.WithDetectorValidation())
}

func (receiver *URLProtocolRelativeCompositeStrategy) getCombinedProtocolRelativeStrategies() ContextualAttackPayloadGenerator {
	javascriptSchemeStrategy := NewSchemeWithNewlineCompositeStrategy(
		NewBasicSchemeDefinition("javascript"),
	)
	obfuscatedJSSchemeStrategy := NewSchemeWithNewlineCompositeStrategy(
		NewMixCasesSchemeDefinition("jaVascrIpt"),
	)
	iteratorStrategy := NewFirstSuccessMetaStrategy(
		javascriptSchemeStrategy,
		obfuscatedJSSchemeStrategy,
	)
	return iteratorStrategy
}


func (receiver *URLProtocolRelativeCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	initialFinding := receiver.A_HgmHnx(probeBuilder, profile)
	if initialFinding == nil {
		return nil
	}
	combinedStrategy := receiver.getCombinedProtocolRelativeStrategies()
	if combinedStrategy == nil {
		return nil
	}
	return combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
