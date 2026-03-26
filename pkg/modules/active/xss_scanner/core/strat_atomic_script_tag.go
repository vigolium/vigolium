package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// BasicScriptTagStrategy implements the ContextualXSSTechnique interface.
type BasicScriptTagStrategy struct {
	tagPrefix       string
	useAdvancedMode bool
}

// NewBasicScriptTagStrategy creates a new instance.
func NewBasicScriptTagStrategy(prefix string, advancedMode bool) *BasicScriptTagStrategy {
	return &BasicScriptTagStrategy{
		tagPrefix:       prefix,
		useAdvancedMode: advancedMode,
	}
}

func (receiver *BasicScriptTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<script>#{poc}</script>#{random_string_5b}"

	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithAdditionalScanFlags(4).
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
