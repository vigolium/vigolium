package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// DataURISchemeCompositeStrategy implements the ContextualXSSTechnique interface.
type DataURISchemeCompositeStrategy struct {
	randomProvider      *utils.RandomGenerator
	dataSchemeDirective SchemeDefinition
	combinedStrategy    ContextualAttackPayloadGenerator
}

func (receiver *DataURISchemeCompositeStrategy) createDataURISubStrategy(
	prefix string,
	suffix string,
) ContextualAttackPayloadGenerator {
	prefixSuffixRandomStrategy := NewSchemePrefixSuffixRandomPayloadStrategy(
		prefix,
		receiver.dataSchemeDirective,
		suffix,
	)
	base64ScriptStrategy := NewDataURIBase64ScriptStrategy(
		receiver.randomProvider,
		prefix,
		suffix,
	)
	return NewSequentialMetaStrategy(
		prefixSuffixRandomStrategy,
		base64ScriptStrategy,
	)
}

// NewDataURISchemeCompositeStrategy creates a new instance.
func NewDataURISchemeCompositeStrategy(
	randomProvider *utils.RandomGenerator,
	dataScheme SchemeDefinition,
) *DataURISchemeCompositeStrategy {
	receiver := &DataURISchemeCompositeStrategy{
		randomProvider:      randomProvider,
		dataSchemeDirective: dataScheme,
		// combinedStrategy is initialized below
	}

	suffixVariations := []string{
		"",
		"\t",
		"\n",
		"\r",
		":",
		"\x00",
	}

	prefixVariations := []string{
		"", " ", "\t", "\n", "\r", "\f", "\b",
		"\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07",
		"\x0b", "\x0e", "\x0f", "\x10", "\x11", "\x12", "\x13",
		"\x14", "\x15", "\x16", "\x17", "\x18", "\x19", "\x1a",
		"\x1b", "\x1c", "\x1d", "\x1e", "\x1f",
	}

	subStrategies := make(
		[]ContextualAttackPayloadGenerator,
		0,
		len(prefixVariations)+len(suffixVariations),
	)

	// Add suffix variations
	for _, currentSuffix := range suffixVariations {
		subStrategies = append(subStrategies, receiver.createDataURISubStrategy("", currentSuffix))

	}

	// Add prefix variations
	for _, currentPrefix := range prefixVariations {
		subStrategies = append(subStrategies, receiver.createDataURISubStrategy(currentPrefix, ""))

	}

	receiver.combinedStrategy = NewFirstSuccessMetaStrategy(subStrategies...)

	return receiver
}

func (receiver *DataURISchemeCompositeStrategy) GeneratePayload(
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
