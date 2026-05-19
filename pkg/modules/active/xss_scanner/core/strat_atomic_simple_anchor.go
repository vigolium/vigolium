package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SimpleAnchorAttributeStrategy implements the ContextualXSSTechnique interface.
type SimpleAnchorAttributeStrategy struct {
	tagPrefix       string
	useAdvancedMode bool
}

// NewSimpleAnchorAttributeStrategy creates a new instance.
func NewSimpleAnchorAttributeStrategy(
	prefix string,
	advancedMode bool,
) *SimpleAnchorAttributeStrategy {
	return &SimpleAnchorAttributeStrategy{
		tagPrefix:       prefix,
		useAdvancedMode: advancedMode,
	}
}

func (receiver *SimpleAnchorAttributeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<a b=c>#{random_string_5b}"

	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(1), formattedPayload, finalProfile)
}
