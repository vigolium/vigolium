package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

type MultiSchemeURLCompositeStrategy struct {
	randomProvider *utils.RandomGenerator
}

// NewMultiSchemeURLCompositeStrategy creates a new instance.
func NewMultiSchemeURLCompositeStrategy(
	randomProvider *utils.RandomGenerator,
) *MultiSchemeURLCompositeStrategy {
	return &MultiSchemeURLCompositeStrategy{
		randomProvider: randomProvider,
	}
}


func (receiver *MultiSchemeURLCompositeStrategy) PreliminaryXSSFinding(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	formattedPayload := "#{random_string_5}:#{random_string_5b}"
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(11), formattedPayload, profile.WithDetectorValidation())
}

func (receiver *MultiSchemeURLCompositeStrategy) getCombinedSchemeStrategies() ContextualAttackPayloadGenerator {
	javascriptStrategy1 := NewSchemeSpecificPayloadCompositeStrategy(
		NewBasicSchemeDefinition("javascript"),
	)
	javascriptStrategy2 := NewSchemeSpecificPayloadCompositeStrategy(
		NewMixCasesSchemeDefinition("jaVascrIpt"),
	)
	javascriptIteratorStrategy := NewFirstSuccessMetaStrategy(
		javascriptStrategy1,
		javascriptStrategy2,
	)

	dataURISchemeStrategy1 := NewDataURISchemeCompositeStrategy(
		receiver.randomProvider,
		NewBasicSchemeDefinition("data"),
	)
	dataURISchemeStrategy2 := NewDataURISchemeCompositeStrategy(
		receiver.randomProvider,
		NewMixCasesSchemeDefinition("daTa"),
	)
	dataURIIteratorStrategy := NewFirstSuccessMetaStrategy(
		dataURISchemeStrategy1,
		dataURISchemeStrategy2,
	)

	vbscriptStrategy1 := NewVBScriptSchemeCompositeStrategy(NewBasicSchemeDefinition("vbscript"))
	vbscriptStrategy2 := NewVBScriptSchemeCompositeStrategy(NewMixCasesSchemeDefinition("vBscrIpt"))
	vbscriptIteratorStrategy := NewFirstSuccessMetaStrategy(vbscriptStrategy1, vbscriptStrategy2)

	prioritizedIterator := NewPrioritizedIteratingMetaStrategy(
		javascriptIteratorStrategy,
		dataURIIteratorStrategy,
		vbscriptIteratorStrategy,
	)

	return prioritizedIterator
}


func (receiver *MultiSchemeURLCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	initialFinding := receiver.PreliminaryXSSFinding(probeBuilder, profile)

	if initialFinding == nil {
		return nil
	}

	combinedSchemeStrategy := receiver.getCombinedSchemeStrategies()
	if combinedSchemeStrategy == nil { // Defensive check, though original doesn't show this before calling .a
		return nil
	}

	return combinedSchemeStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
