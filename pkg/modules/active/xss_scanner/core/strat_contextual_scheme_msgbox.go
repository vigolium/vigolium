package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeMsgboxPayloadStrategy implements the ContextualXSSTechnique interface.
type SchemeMsgboxPayloadStrategy struct {
	scheme SchemeDefinition
}

// NewSchemeMsgboxPayloadStrategy creates a new instance.
func NewSchemeMsgboxPayloadStrategy(scheme SchemeDefinition) *SchemeMsgboxPayloadStrategy {
	return &SchemeMsgboxPayloadStrategy{
		scheme: scheme,
	}
}

func (strategy *SchemeMsgboxPayloadStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := strategy.scheme.SchemeName() + ":msgbox(#{random_numeric_string_8})"

	combinedScanFlags := 16388 | strategy.scheme.SchemeFlag()
	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(combinedScanFlags)

	finalProfile := profile.WithDetectorValidation()

	return adjustedProbeBuilder.BuildFinding(byte(11), formattedPayload, finalProfile)
}
