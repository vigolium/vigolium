package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptSemicolonInjectionStrategy implements the ContextualXSSTechnique interface.
// Original Java class: dgl
type JavaScriptSemicolonInjectionStrategy struct {
	delegateStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewJavaScriptSemicolonInjectionStrategy creates a new instance of Dgl.
// Original Java constructor: dgl(am_ var1, boolean var2)
func NewJavaScriptSemicolonInjectionStrategy(
	params JavaScriptPayloadParams,
	useHTMLEntityVariants bool,
) *JavaScriptSemicolonInjectionStrategy {
	// Original Java logic: this.a = new g4h(var1.c + ";", var1.a + ";", var2);

	// Create the g4h instance (NewG4h is a stub that returns ContextualXSSTechnique)
	numericStringVariantStrategy := NewJSNumericStringVariantCompositeStrategy(
		params.primaryComponent+";",
		params.encodedComponent+";",
		useHTMLEntityVariants,
	)

	return &JavaScriptSemicolonInjectionStrategy{
		delegateStrategy: numericStringVariantStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Dgl.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JavaScriptSemicolonInjectionStrategy) GeneratePayload(
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
