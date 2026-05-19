package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// CaseVariantScriptTagStrategy implements the ContextualXSSTechnique interface.
type CaseVariantScriptTagStrategy struct {
	tagPrefix       string
	useAdvancedMode bool
}

// NewCaseVariantScriptTagStrategy creates a new instance.
func NewCaseVariantScriptTagStrategy(
	prefix string,
	advancedMode bool,
) *CaseVariantScriptTagStrategy {
	return &CaseVariantScriptTagStrategy{
		tagPrefix:       prefix,
		useAdvancedMode: advancedMode,
	}
}

func (receiver *CaseVariantScriptTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<ScRiPt>#{poc}</ScRiPt>#{random_string_5b}"

	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithAdditionalScanFlags(12).
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
