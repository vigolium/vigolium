package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// HTMLEntityVariantCompositeStrategy implements the ContextualXSSTechnique interface.
type HTMLEntityVariantCompositeStrategy struct {
	variantGeneratingStrategy ContextualAttackPayloadGenerator
}

// It uses a map to simulate Set<String> behavior regarding uniqueness.
func (receiver *HTMLEntityVariantCompositeStrategy) generateHTMLEntityVariations(
	baseString string,
) map[string]struct{} {
	variationsSet := make(map[string]struct{})

	variationsSet[strings.ReplaceAll(baseString, "\"", "&quot;")] = struct{}{}
	variationsSet[strings.ReplaceAll(baseString, "\"", "&#x22;")] = struct{}{}
	variationsSet[strings.ReplaceAll(baseString, "\"", "&#34;")] = struct{}{}
	variationsSet[strings.ReplaceAll(baseString, "'", "&apos;")] = struct{}{}
	variationsSet[strings.ReplaceAll(baseString, "'", "&#x27;")] = struct{}{}
	variationsSet[strings.ReplaceAll(baseString, "'", "&#39;")] = struct{}{}

	delete(variationsSet, baseString)

	return variationsSet
}

// NewHTMLEntityVariantCompositeStrategy creates a new instance.
func NewHTMLEntityVariantCompositeStrategy(
	baseString string,
	useEntityVariants bool,
	strategyFactory StrategyGeneratorFromString,
) *HTMLEntityVariantCompositeStrategy {
	receiver := &HTMLEntityVariantCompositeStrategy{}


	payloadBases := make([]string, 0)

	payloadBases = append(payloadBases, baseString)

	if useEntityVariants {
		for variant := range receiver.generateHTMLEntityVariations(baseString) {
			payloadBases = append(payloadBases, variant)
		}
	}

	generatedStrategies := make([]ContextualAttackPayloadGenerator, len(payloadBases))

	index := 0
	for index < len(payloadBases) {
		generatedStrategies[index] = strategyFactory.CreateStrategy(
			payloadBases[index],
		)
		index++
	}

	receiver.variantGeneratingStrategy = NewFirstSuccessMetaStrategy(
		generatedStrategies...)

	return receiver
}

func (receiver *HTMLEntityVariantCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return receiver.variantGeneratingStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
