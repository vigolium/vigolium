package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ImageOnErrorStrategy implements the ContextualXSSTechnique interface.
type ImageOnErrorStrategy struct {
	tagPrefix       string
	useAdvancedMode bool
}

// NewImageOnErrorStrategy creates a new instance.
func NewImageOnErrorStrategy(prefix string, advancedMode bool) *ImageOnErrorStrategy {
	return &ImageOnErrorStrategy{
		tagPrefix:       prefix,
		useAdvancedMode: advancedMode,
	}
}

func (receiver *ImageOnErrorStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<img src=a onerror=#{poc}>#{random_string_5b}"

	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(1), formattedPayload, finalProfile)
}
