package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ProcessedClosingTagStrategy implements the ContextualXSSTechnique interface.
type ProcessedClosingTagStrategy struct {
	tagName            string
	payloadContextCode byte
}

// NewProcessedClosingTagStrategy creates a new instance.
func NewProcessedClosingTagStrategy(tagName string, contextCode byte) *ProcessedClosingTagStrategy {
	return &ProcessedClosingTagStrategy{
		tagName:            tagName,
		payloadContextCode: contextCode,
	}
}

func (receiver *ProcessedClosingTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	mangledTagName := mangleTagNameForClosing(receiver.tagName)
	formattedPayload := "#{random_string_5}</" + mangledTagName + " >#{random_string_5b}"

	return probeBuilder.WithAdditionalScanFlags(8).
		WithoutSecondaryCanary().
		BuildFinding(receiver.payloadContextCode, formattedPayload, profile)
}
