package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeWithRandomStringStrategy implements the ContextualXSSTechnique interface.
type SchemeWithRandomStringStrategy struct {
	scheme        SchemeDefinition
	payloadSuffix string
}

// NewSchemeWithRandomStringStrategy creates a new instance.
func NewSchemeWithRandomStringStrategy(
	scheme SchemeDefinition,
	suffix string,
) *SchemeWithRandomStringStrategy {
	return &SchemeWithRandomStringStrategy{
		scheme:        scheme,
		payloadSuffix: suffix,
	}
}

func (strategy *SchemeWithRandomStringStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := strategy.scheme.SchemeName() + ":" + strategy.payloadSuffix + "#{random_string_8}"

	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(strategy.scheme.SchemeFlag())

	finalProfile := profile.WithDetectorValidation()

	return adjustedProbeBuilder.BuildFinding(byte(11), formattedPayload, finalProfile)
}
