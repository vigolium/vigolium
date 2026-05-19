package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JSStringFromComponentsStrategy implements the ContextualXSSTechnique interface.
type JSStringFromComponentsStrategy struct {
	components JSStringPayloadComponents
}

// NewJSStringFromComponentsStrategy creates a new instance.
func NewJSStringFromComponentsStrategy(
	components JSStringPayloadComponents,
) *JSStringFromComponentsStrategy {
	return &JSStringFromComponentsStrategy{
		components: components,
	}
}

func (receiver *JSStringFromComponentsStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	mainFormattedPayload := "#{random_string_5}" + receiver.components.payloadWithBaseSuffix + "#{poc}" + receiver.components.baseSuffix + "#{random_string_5b}"

	profilePayloadComponent := "#{random_string_5}" + receiver.components.encodedPayloadWithBaseSuffix + "#{poc}" + receiver.components.encodedBaseSuffix + "#{random_string_5b}"

	finalProfile := profile.WithVariantCanaryComponent(profilePayloadComponent)

	return probeBuilder.WithAdditionalScanFlags(4).
		BuildFinding(byte(3), mainFormattedPayload, finalProfile)
}
