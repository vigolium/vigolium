package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeWithRandomStringAdvancedStrategy implements the ContextualXSSTechnique interface.
type SchemeWithRandomStringAdvancedStrategy struct {
	scheme SchemeDefinition
}

// NewSchemeWithRandomStringAdvancedStrategy creates a new instance.
func NewSchemeWithRandomStringAdvancedStrategy(
	scheme SchemeDefinition,
) *SchemeWithRandomStringAdvancedStrategy {
	return &SchemeWithRandomStringAdvancedStrategy{
		scheme: scheme,
	}
}

func (receiver *SchemeWithRandomStringAdvancedStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := receiver.scheme.SchemeName() + ":#{random_string_8}"

	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(receiver.scheme.SchemeFlag())

	finalProfile := profile.WithDetectorValidation()

	return adjustedProbeBuilder.BuildFinding(byte(11), formattedPayload, finalProfile)
}
