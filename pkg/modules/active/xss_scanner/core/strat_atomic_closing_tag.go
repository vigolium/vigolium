package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ClosingTagStrategy implements the ContextualXSSTechnique interface.
type ClosingTagStrategy struct {
	tagName            string
	payloadContextCode byte
}

// NewClosingTagStrategy creates a new instance.
func NewClosingTagStrategy(tagName string, contextCode byte) *ClosingTagStrategy {
	return &ClosingTagStrategy{
		tagName:            tagName,
		payloadContextCode: contextCode,
	}
}

func (receiver *ClosingTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	closingTagString := "</" + receiver.tagName + ">"

	formattedPayload := "#{random_string_5}" + closingTagString + "#{random_string_5b}"

	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(receiver.payloadContextCode, formattedPayload, profile)
}
