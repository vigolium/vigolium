package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// ScriptSchemeInAttributeStrategy implements the ContextualXSSTechnique interface.
type ScriptSchemeInAttributeStrategy struct {
	contentTypeProfile *ContentTypeProfile
}

func isJavaScriptScheme(reflection ReflectionOccurrenceDetail) bool {
	attributeReflection, isCorrectType := reflection.(*HTMLAttributeReflection)
	if !isCorrectType ||
		attributeReflection == nil {
		return false // Or handle error appropriately
	}
	return strings.HasPrefix(attributeReflection.attributeValue, "javascript:")
}

// javaScriptSchemeMatcher implements the ReflectionMatcher interface for JavaScript scheme detection.
type javaScriptSchemeMatcher struct{}

func (w *javaScriptSchemeMatcher) Matches(
	reflection ReflectionOccurrenceDetail,
) bool {
	return isJavaScriptScheme(reflection)
}

func (w *javaScriptSchemeMatcher) IsReflectionMatchCriterion() {} // To satisfy ReflectionMatcher interface if it has marker methods

// NewScriptSchemeInAttributeStrategy creates a new instance.
func NewScriptSchemeInAttributeStrategy(
	contentType *ContentTypeProfile,
) *ScriptSchemeInAttributeStrategy {
	return &ScriptSchemeInAttributeStrategy{
		contentTypeProfile: contentType,
	}
}

func (strategy *ScriptSchemeInAttributeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	attributeReflection, isCorrectType := reflection.(*HTMLAttributeReflection)

	if !isCorrectType ||
		attributeReflection == nil {
		return nil
	}

	if !strings.HasPrefix(attributeReflection.attributeValue, "javascript:") {
		return nil
	}

	coreReflectionInfo := attributeReflection.CoreInfo()
	analyzedContextCode := GetByteContextAfterDecoding(
		transaction.GetResponseBody(),
		coreReflectionInfo.GetStartIndex(),
		coreReflectionInfo.GetEndIndex(),
	)

	mappedStrategyBuilder := NewMappedStrategyBuilder()
	jsStringDoubleQuoteStrategy := NewJavaScriptStringBreakoutStrategy("\"", strategy.contentTypeProfile, true)
	jsStringSingleQuoteStrategy := NewJavaScriptStringBreakoutStrategy("'", strategy.contentTypeProfile, true)
	jsStatementStrategy := NewJavaScriptStatementCompositeStrategy()

	schemeFilter := &javaScriptSchemeMatcher{}
	profileWithFilter := profile.WithAdditionalMatchCriterion(schemeFilter)

	mappedExecutor := mappedStrategyBuilder.AddStrategy(byte(0), jsStringDoubleQuoteStrategy).
		AddStrategy(byte(1), jsStringSingleQuoteStrategy).
		AddStrategy(byte(2), jsStatementStrategy).
		Build()

	return mappedExecutor.ExecuteStrategyByCode(
		analyzedContextCode,
		probeBuilder,
		profileWithFilter,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
