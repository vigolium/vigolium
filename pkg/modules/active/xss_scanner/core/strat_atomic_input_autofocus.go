package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// InputAutofocusOnfocusStrategy implements the ContextualXSSTechnique interface.
type InputAutofocusOnfocusStrategy struct {
	tagPrefix       string
	useAdvancedMode bool
}

// NewInputAutofocusOnfocusStrategy creates a new instance.
func NewInputAutofocusOnfocusStrategy(
	prefix string,
	advancedMode bool,
) *InputAutofocusOnfocusStrategy {
	return &InputAutofocusOnfocusStrategy{
		tagPrefix:       prefix,
		useAdvancedMode: advancedMode,
	}
}

func (receiver *InputAutofocusOnfocusStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<input type=text autofocus onfocus=#{poc}//#{random_string_5b}"

	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)
	return probeBuilder.WithAdditionalScanFlags(36).
		BuildFinding(byte(1), formattedPayload, finalProfile)
}
