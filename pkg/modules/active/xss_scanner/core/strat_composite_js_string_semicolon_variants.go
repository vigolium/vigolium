package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JSStringSemicolonVariantStrategy implements the ContextualXSSTechnique interface.
// Original Java class: ctw
type JSStringSemicolonVariantStrategy struct {
	delegateStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewJSStringSemicolonVariantStrategy creates a new instance of Ctw.
// Original Java constructor: ctw(am_ var1, boolean var2)
func NewJSStringSemicolonVariantStrategy(
	baseParams JavaScriptPayloadParams,
	useHTMLEntityVariants bool,
) *JSStringSemicolonVariantStrategy {
	// Original Java logic for initializing field 'a':
	// this.a = new fdz(new am_(var1.c + ";", var1.a + ";", var1.b), var2);

	paramsWithSemicolon := JavaScriptPayloadParams{
		primaryComponent: baseParams.primaryComponent + ";",
		encodedComponent: baseParams.encodedComponent + ";",
		flag:             baseParams.flag,
	}

	encodedVariantStrategy := NewEncodedJSStringVariantStrategy(
		paramsWithSemicolon,
		useHTMLEntityVariants,
	) // NewFdz is ported

	return &JSStringSemicolonVariantStrategy{
		delegateStrategy: encodedVariantStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Ctw.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JSStringSemicolonVariantStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return this.a.a(var1, var2, var3, var4, var5, var6);
	return receiver.delegateStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
