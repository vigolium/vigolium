package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptSimpleCallStrategy implements the ContextualAttackPayloadGenerator interface.
type JavaScriptSimpleCallStrategy struct {
}

// NewJavaScriptSimpleCallStrategy creates a new instance.
func NewJavaScriptSimpleCallStrategy() *JavaScriptSimpleCallStrategy {
	return &JavaScriptSimpleCallStrategy{}
}

func (receiver *JavaScriptSimpleCallStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := "#{random_string_5}(a)#{random_string_5b}"
	return probeBuilder.WithoutSecondaryCanary().BuildFinding(byte(3), formattedPayload, profile)
}
