package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// EncodedJavaScriptSchemeCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: ao9
type EncodedJavaScriptSchemeCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewEncodedJavaScriptSchemeCompositeStrategy creates a new instance of Ao9.
// Original Java constructor: ao9(ou var1)
func NewEncodedJavaScriptSchemeCompositeStrategy(
	randomProvider *utils.RandomGenerator,
) *EncodedJavaScriptSchemeCompositeStrategy {
	// Original Java logic: this.a = new gfw(new hcb(var1), new hcv(), new dtt());
	// Ported logic:
	// new hcb(var1) -> NewHcb(var1)
	// new hcv()     -> NewHcv()
	// new dtt()     -> NewDtt()
	// new gfw(...)  -> NewGfw(...)
	return &EncodedJavaScriptSchemeCompositeStrategy{
		combinedStrategy: NewFirstSuccessMetaStrategy(
			NewMultiSchemeURLCompositeStrategy(randomProvider),
			NewURLProtocolRelativeCompositeStrategy(),
			NewHTMLEncodedJavaScriptSchemeStrategy(),
		),
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Ao9.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *EncodedJavaScriptSchemeCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var5.a().f != var5.a().c ? null : this.a.a(var1, var2, var3, var4, var5, var6);
	// Ported logic:
	// var5.a() -> eqxVal.A()
	// .f       -> .GetF()
	// .c       -> .GetC()
	coreReflectionInfo := reflection.CoreInfo() // hpoVal is the result of eqxVal.A(), equivalent to Java var5.a()

	if coreReflectionInfo.GetStartIndex() != coreReflectionInfo.GetEndIndex() {
		return nil
	}

	return receiver.combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
