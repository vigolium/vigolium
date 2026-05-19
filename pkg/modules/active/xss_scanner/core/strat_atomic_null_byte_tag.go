package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// NullByteInTagStrategy implements the ContextualXSSTechnique interface.
type NullByteInTagStrategy struct {
	useAdvancedMode bool
	tagPrefix       string
}

// NewNullByteInTagStrategy creates a new instance.
func NewNullByteInTagStrategy(advancedMode bool, prefix string) *NullByteInTagStrategy {
	return &NullByteInTagStrategy{
		useAdvancedMode: advancedMode,
		tagPrefix:       prefix,
	}
}

func (receiver *NullByteInTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := receiver.tagPrefix + "<\x00#{random_invalid_tag_name_5}>"

	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithoutSecondaryCanary().
		WithAdditionalScanFlags(32768).
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
