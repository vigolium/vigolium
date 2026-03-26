package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// InputTextAutofocusOnfocusStrategy implements the ContextualXSSTechnique interface.
type InputTextAutofocusOnfocusStrategy struct {
	prefix           string
	randomComponent1 string
	attributeSpacing string
	quoteChar        string
	useAdvancedMode  bool
}

// NewInputTextAutofocusOnfocusStrategy creates a new instance.
func NewInputTextAutofocusOnfocusStrategy(
	prefix, randomComponent1, attributeSpacing, quoteChar string,
	useAdvancedMode bool,
) *InputTextAutofocusOnfocusStrategy {
	return &InputTextAutofocusOnfocusStrategy{
		prefix:           prefix,
		randomComponent1: randomComponent1,
		attributeSpacing: attributeSpacing,
		quoteChar:        quoteChar,
		useAdvancedMode:  useAdvancedMode,
	}
}

func (receiver *InputTextAutofocusOnfocusStrategy) getFocusAttributeSpacing() string {
	if receiver.attributeSpacing != "" {
		return receiver.attributeSpacing
	}
	return " "
}

func (receiver *InputTextAutofocusOnfocusStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := receiver.prefix +
		"#{random_string_5}" +
		receiver.randomComponent1 +
		receiver.attributeSpacing +
		"type=" +
		receiver.quoteChar +
		"text" +
		receiver.quoteChar +
		receiver.attributeSpacing +
		"autofocus" +
		receiver.getFocusAttributeSpacing() +
		"onfocus=" +
		receiver.quoteChar +
		"#{poc}" +
		receiver.quoteChar +
		"//#{random_string_5b}"

	finalProfile := profile.WithAdditionalMatchCriterion(NewContextSpecificReflectionMatcher(contextType)).
		WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithAdditionalScanFlags(36).
		BuildFinding(byte(2), formattedPayload, finalProfile)
}
