package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// TagBreakoutStrategy implements the ContextualXSSTechnique interface.
type TagBreakoutStrategy struct {
	useAdvancedMode bool
	tagPrefix       string
}

// NewTagBreakoutStrategy creates a new instance.
func NewTagBreakoutStrategy(advancedMode bool, prefix string) *TagBreakoutStrategy {
	return &TagBreakoutStrategy{
		useAdvancedMode: advancedMode,
		tagPrefix:       prefix,
	}
}

func (receiver *TagBreakoutStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := "#{random_string_10}" + receiver.tagPrefix + "><"

	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
