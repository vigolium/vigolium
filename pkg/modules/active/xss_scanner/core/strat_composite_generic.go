package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// GenericXSSCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fa9
type GenericXSSCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewGenericXSSCompositeStrategy creates a new instance of Fa9.
// Original Java constructor: fa9(String var1, boolean var2)
func NewGenericXSSCompositeStrategy(
	prefix string,
	useAdvancedMode bool,
) *GenericXSSCompositeStrategy {
	// Original Java logic:
	// this.a = new gfw(new b0q(var1),
	//    new e_w(new b3d(var2, var1),
	//        new gfw(new fft(var2, var1),
	//                  new gem(var2, var1),
	//                  new a6o(var2, var1),
	//                  new dxe(var2, var1)
	//                 )
	//           )
	//        );

	// b0qInst := NewB0q(strVar1)           // Ported
	// b3dInst := NewB3d(boolVar2, strVar1) // Ported

	// fftInst := NewFft(boolVar2, strVar1) // Stubbed
	// gemInst := NewGem(boolVar2, strVar1) // Stubbed
	// a6oInst := NewA6o(boolVar2, strVar1) // Ported
	// dxeInst := NewDxe(boolVar2, strVar1) // Ported

	// gfwInner := NewGfw(fftInst, gemInst, a6oInst, dxeInst) // Stubbed Gfw
	// ewInst := NewEW(b3dInst, gfwInner)                     // Ported EW

	// finalCombinedStrategy := NewGfw(b0qInst, ewInst)
	finalCombinedStrategy := NewFirstSuccessMetaStrategy(
		NewSimpleAnchorTagStrategy(prefix),
		NewPairedStrategyExecutor(
			NewTagBreakoutStrategy(useAdvancedMode, prefix),
			NewFirstSuccessMetaStrategy(
				NewAngleBracketInvalidTagStrategy(useAdvancedMode, prefix),
				NewInvalidDoubleAngleTagStrategy(useAdvancedMode, prefix),
				NewNullByteInTagStrategy(useAdvancedMode, prefix),
				NewServerSideTagSyntaxStrategy(useAdvancedMode, prefix),
			),
		),
	)

	return &GenericXSSCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Fa9.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *GenericXSSCompositeStrategy) GeneratePayload(
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
