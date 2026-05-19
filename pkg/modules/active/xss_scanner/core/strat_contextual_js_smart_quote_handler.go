package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptSmartQuoteHandlerStrategy implements the ContextualXSSTechnique interface.
type JavaScriptSmartQuoteHandlerStrategy struct {
	contentTypeProfile *ContentTypeProfile
}

func NewJavaScriptSmartQuoteHandlerStrategy(
	contentType *ContentTypeProfile,
) *JavaScriptSmartQuoteHandlerStrategy {
	return &JavaScriptSmartQuoteHandlerStrategy{
		contentTypeProfile: contentType,
	}
}

func (receiver *JavaScriptSmartQuoteHandlerStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	coreReflectionInfo := reflection.CoreInfo()
	analyzedContextCode := GetByteContextAfterDecoding(
		transaction.GetResponseBody(),
		coreReflectionInfo.GetStartIndex(),
		coreReflectionInfo.GetEndIndex(),
	)

	mappedStrategyBuilder := NewMappedStrategyBuilder()
	jsStringDoubleQuoteStrategy := NewJavaScriptStringBreakoutStrategy(
		"\"",
		receiver.contentTypeProfile,
		true,
	)
	jsStringSingleQuoteStrategy := NewJavaScriptStringBreakoutStrategy(
		"'",
		receiver.contentTypeProfile,
		true,
	)
	jsStatementStrategy := NewJavaScriptStatementCompositeStrategy()

	mappedExecutor := mappedStrategyBuilder.AddStrategy(byte(0), jsStringDoubleQuoteStrategy).
		AddStrategy(byte(1), jsStringSingleQuoteStrategy).
		AddStrategy(byte(2), jsStatementStrategy).
		Build()

	return mappedExecutor.ExecuteStrategyByCode(
		analyzedContextCode,
		probeBuilder.WithAdditionalScanFlags(1024),
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
