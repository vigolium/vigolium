package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ServerSideTagSyntaxStrategy implements the ContextualXSSTechnique interface.
type ServerSideTagSyntaxStrategy struct {
	useAdvancedMode bool
	tagPrefix       string
}

// NewServerSideTagSyntaxStrategy creates a new instance.
func NewServerSideTagSyntaxStrategy(advancedMode bool, prefix string) *ServerSideTagSyntaxStrategy {
	return &ServerSideTagSyntaxStrategy{
		useAdvancedMode: advancedMode,
		tagPrefix:       prefix,
	}
}

func (receiver *ServerSideTagSyntaxStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := receiver.tagPrefix + "<%#{random_invalid_tag_name_5}>"

	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithAdditionalScanFlags(32768).
		WithoutSecondaryCanary().
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
