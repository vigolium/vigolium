package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JSInHTMLGenericCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: amy
type JSInHTMLGenericCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewJSInHTMLGenericCompositeStrategy creates a new instance of Amy.
// Original Java constructor: public amy(def var1)
func NewJSInHTMLGenericCompositeStrategy(
	contentType *ContentTypeProfile,
) *JSInHTMLGenericCompositeStrategy {
	// Original Java logic: this.a = new gfw(new at6(var1), new h9c());
	// Ported logic:
	// new at6(var1) -> NewAt6(var1)
	// new h9c()     -> NewH9c()
	// new gfw(...)  -> NewGfw(...)
	// Ensure the NewGfw, NewAt6, NewH9c stubs return ContextualXSSTechnique or types that implement ContextualXSSTechnique.
	return &JSInHTMLGenericCompositeStrategy{
		combinedStrategy: NewFirstSuccessMetaStrategy(
			NewJavaScriptSmartQuoteHandlerStrategy(contentType),
			NewTagAttributeUnquotedCompositeStrategy(),
		),
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Amy.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JSInHTMLGenericCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return this.a.a(var1, var2, var3, var4, var5, var6);
	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
