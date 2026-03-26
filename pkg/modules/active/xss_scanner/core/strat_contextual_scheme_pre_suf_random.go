package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemePrefixSuffixRandomPayloadStrategy implements the ContextualXSSTechnique interface.
type SchemePrefixSuffixRandomPayloadStrategy struct {
	payloadPrefix string
	scheme        SchemeDefinition
	payloadSuffix string
}

// NewSchemePrefixSuffixRandomPayloadStrategy creates a new instance.
func NewSchemePrefixSuffixRandomPayloadStrategy(
	prefix string,
	scheme SchemeDefinition,
	suffix string,
) *SchemePrefixSuffixRandomPayloadStrategy {
	return &SchemePrefixSuffixRandomPayloadStrategy{
		payloadPrefix: prefix,
		scheme:        scheme,
		payloadSuffix: suffix,
	}
}

func (strategy *SchemePrefixSuffixRandomPayloadStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := strategy.payloadPrefix + strategy.scheme.SchemeName() + strategy.payloadSuffix + ":#{random_string_8}"

	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(strategy.scheme.SchemeFlag())
	finalProfile := profile.WithDetectorValidation()

	return adjustedProbeBuilder.BuildFinding(byte(11), formattedPayload, finalProfile)
}
