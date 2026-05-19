package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SimpleAnchorTagStrategy implements the ContextualXSSTechnique interface.
type SimpleAnchorTagStrategy struct {
	tagPrefix string
}

// NewSimpleAnchorTagStrategy creates a new instance.
func NewSimpleAnchorTagStrategy(prefix string) *SimpleAnchorTagStrategy {
	return &SimpleAnchorTagStrategy{
		tagPrefix: prefix,
	}
}

func (receiver *SimpleAnchorTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<a>#{random_string_5b}"
	return probeBuilder.WithoutSecondaryCanary().BuildFinding(byte(0), formattedPayload, profile)
}
