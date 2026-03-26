package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// AngleBracketInvalidTagStrategy implements the ContextualXSSTechnique interface.
type AngleBracketInvalidTagStrategy struct {
	useAdvancedMode bool
	tagPrefix       string
}

// NewAngleBracketInvalidTagStrategy creates a new instance.
func NewAngleBracketInvalidTagStrategy(
	advancedMode bool,
	prefix string,
) *AngleBracketInvalidTagStrategy {
	return &AngleBracketInvalidTagStrategy{
		useAdvancedMode: advancedMode,
		tagPrefix:       prefix,
	}
}

func (receiver *AngleBracketInvalidTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := receiver.tagPrefix + "<#{random_invalid_tag_name_5}>"
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
