package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeWithPocAndRandomStringStrategy implements the ContextualXSSTechnique interface.
type SchemeWithPocAndRandomStringStrategy struct {
	scheme        SchemeDefinition
	payloadSuffix string
}

// NewSchemeWithPocAndRandomStringStrategy creates a new instance.
func NewSchemeWithPocAndRandomStringStrategy(
	scheme SchemeDefinition,
	suffix string,
) *SchemeWithPocAndRandomStringStrategy {
	return &SchemeWithPocAndRandomStringStrategy{
		scheme:        scheme,
		payloadSuffix: suffix,
	}
}

func (strategy *SchemeWithPocAndRandomStringStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := strategy.scheme.SchemeName() + ":" + strategy.payloadSuffix + "#{poc}//#{random_string_8}"

	combinedScanFlags := 4 | strategy.scheme.SchemeFlag()
	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(combinedScanFlags)

	finalProfile := profile.WithDetectorValidation()

	return adjustedProbeBuilder.BuildFinding(
		byte(11),
		formattedPayload,
		finalProfile,
	)
}
