package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ConditionalScriptTagCheckMetaStrategy implements the ContextualXSSTechnique interface.
// Original Java class: dw1
type ConditionalScriptTagCheckMetaStrategy struct {
	delegateStrategy   ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
	contentTypeProfile *ContentTypeProfile              // Corresponds to 'private final def b;' // Changed to *Def
	skipIfScript       bool                             // Corresponds to 'private final boolean c;'
}

// NewConditionalScriptTagCheckMetaStrategy creates a new instance of Dw1.
// Original Java constructor: dw1(def var1, boolean var2)
func NewConditionalScriptTagCheckMetaStrategy(
	contentType *ContentTypeProfile,
	skipIfScript bool,
) *ConditionalScriptTagCheckMetaStrategy { // Changed defVar1 to *Def
	// Original Java logic for initializing field 'a':
	// this.a = new fo0("script", (byte)5);
	tagBreakoutStrategy := NewSpecificTagBreakoutCompositeStrategy(
		"script",
		byte(5),
	) // NewFo0 is a stub that returns ContextualXSSTechnique

	return &ConditionalScriptTagCheckMetaStrategy{
		delegateStrategy:   tagBreakoutStrategy,
		contentTypeProfile: contentType,
		skipIfScript:       skipIfScript,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Dw1.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (strategy *ConditionalScriptTagCheckMetaStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return !this.c && this.b.g != 259 ? this.a.a(var1, var2, var3, var4, var5, var6) : null;
	// 259 corresponds to DefTypeScript

	if strategy.contentTypeProfile != nil && !strategy.skipIfScript &&
		strategy.contentTypeProfile.GetInferredTypeCode() != DefTypeScript {
		return strategy.delegateStrategy.GeneratePayload(
			probeBuilder,
			profile,
			tactic,
			contextType,
			reflection,
			transaction,
		)
	}
	return nil
}
