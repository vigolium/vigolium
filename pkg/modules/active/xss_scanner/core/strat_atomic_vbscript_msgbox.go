package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// VBScriptMsgboxStrategy implements the ContextualXSSTechnique interface.
type VBScriptMsgboxStrategy struct {
	delimiter string
}

// NewVBScriptMsgboxStrategy creates a new instance.
func NewVBScriptMsgboxStrategy(delimiter string) *VBScriptMsgboxStrategy {
	return &VBScriptMsgboxStrategy{
		delimiter: delimiter,
	}
}

func (receiver *VBScriptMsgboxStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	formattedPayload := "#{random_numeric_string_5}" + receiver.delimiter + "&msgbox(1)&" + receiver.delimiter + "#{random_numeric_string_3}"

	return probeBuilder.WithoutSecondaryCanary().
		WithAdditionalScanFlags(16388).
		BuildFinding(byte(13), formattedPayload, profile)
}
