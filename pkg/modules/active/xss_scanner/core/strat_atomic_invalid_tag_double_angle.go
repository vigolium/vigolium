package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// InvalidDoubleAngleTagStrategy implements the ContextualXSSTechnique interface.
type InvalidDoubleAngleTagStrategy struct {
	useAdvancedMode bool
	tagPrefix       string
}

// NewInvalidDoubleAngleTagStrategy creates a new instance.
func NewInvalidDoubleAngleTagStrategy(
	useAdvancedMode bool,
	tagPrefix string,
) *InvalidDoubleAngleTagStrategy {
	return &InvalidDoubleAngleTagStrategy{
		useAdvancedMode: useAdvancedMode,
		tagPrefix:       tagPrefix,
	}
}

func (receiver *InvalidDoubleAngleTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := receiver.tagPrefix + "<#{random_invalid_tag_name_5}<"
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
