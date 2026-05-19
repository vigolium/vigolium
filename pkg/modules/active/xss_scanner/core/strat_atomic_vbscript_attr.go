package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// VBScriptAttributeStrategy implements the ContextualXSSTechnique interface.
type VBScriptAttributeStrategy struct {
}

// NewVBScriptAttributeStrategy creates a new instance.
func NewVBScriptAttributeStrategy() *VBScriptAttributeStrategy {
	return &VBScriptAttributeStrategy{}
}

func (receiver *VBScriptAttributeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	attributeReflection, isCorrectType := reflection.(*HTMLAttributeReflection)

	if !isCorrectType || attributeReflection == nil {
		return nil
	}

	if !strings.HasPrefix(strings.ToLower(attributeReflection.attributeValue), "vbscript:") {
		return nil
	}

	coreReflectionInfo := attributeReflection.CoreInfo()
	if coreReflectionInfo == nil {
		return nil
	}
	analyzedContextCode := GetByteContextAfterDecoding(
		transaction.GetResponseBody(),
		coreReflectionInfo.GetStartIndex(),
		coreReflectionInfo.GetEndIndex(),
	)

	mappedStrategyBuilder := NewMappedStrategyBuilder()
	vbscriptMsgboxWithQuoteStrategy := NewVBScriptMsgboxStrategy("\"")
	vbscriptMsgboxNoQuoteStrategy := NewVBScriptMsgboxStrategy("")
	mappedExecutor := mappedStrategyBuilder.AddStrategy(byte(0), vbscriptMsgboxWithQuoteStrategy).
		AddStrategy(byte(2), vbscriptMsgboxNoQuoteStrategy).
		Build()

	return mappedExecutor.ExecuteStrategyByCode(
		analyzedContextCode,
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
