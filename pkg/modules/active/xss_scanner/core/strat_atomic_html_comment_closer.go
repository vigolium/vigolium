package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// HTMLCommentCloserStrategy implements the ContextualXSSTechnique interface.
type HTMLCommentCloserStrategy struct {
}

// NewHTMLCommentCloserStrategy creates a new instance.
func NewHTMLCommentCloserStrategy() *HTMLCommentCloserStrategy {
	return &HTMLCommentCloserStrategy{}
}

func (receiver *HTMLCommentCloserStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	formattedPayload := "#{random_string_5}-->#{random_string_5b}"
	return probeBuilder.WithoutSecondaryCanary().BuildFinding(byte(8), formattedPayload, profile)
}
