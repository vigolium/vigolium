package core

import (
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// GenericBreakoutCompositeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: epq
type GenericBreakoutCompositeStrategy struct {
	combinedStrategy ContextualAttackPayloadGenerator // Corresponds to 'private final ContextualXSSTechnique a;'
}

// NewGenericBreakoutCompositeStrategy creates a new instance of Epq.
// Original Java constructor: public epq(String var1, boolean var2)
func NewGenericBreakoutCompositeStrategy(
	prefix string,
	useAdvancedMode bool,
) *GenericBreakoutCompositeStrategy {
	// this.a = new c0b(
	//    new fa9(var1, var2),
	//    new gfw(new fs4(var1, var2), new bfn(var1, var2),
	//        new c0b(new deb(var1, var2),
	//            new gfw(new hpa(var1, var2), new f_6(var1, var2))))
	// );

	// fa9Instance := NewFa9(strVar1, boolVar2)
	// fs4Instance := NewFs4(strVar1, boolVar2)
	// bfnInstance := NewBfn(strVar1, boolVar2) // Ported
	// debInstance := NewDeb(strVar1, boolVar2) // Ported
	// hpaInstance := NewHpa(strVar1, boolVar2) // Ported
	// f6Instance := NewF6(strVar1, boolVar2)   // Stubbed

	// gfwInnerMost := NewGfw(hpaInstance, f6Instance)
	// c0bInner := NewC0b(debInstance, gfwInnerMost) // Ported NewC0b
	// gfwOuter := NewGfw(fs4Instance, bfnInstance, c0bInner)

	// mainC0b := NewC0b(fa9Instance, gfwOuter)

	zap.L().Debug("[Epq] creating strategy",
		zap.String("prefix", prefix),
		zap.Bool("useAdvancedMode", useAdvancedMode))
	finalCombinedStrategy := NewSequentialMetaStrategy(
		NewGenericXSSCompositeStrategy(prefix, useAdvancedMode),
		NewFirstSuccessMetaStrategy(
			NewBasicScriptTagStrategy(prefix, useAdvancedMode),
			NewCaseVariantScriptTagStrategy(prefix, useAdvancedMode),
			NewSequentialMetaStrategy(
				NewSimpleAnchorAttributeStrategy(prefix, useAdvancedMode),
				NewFirstSuccessMetaStrategy(
					NewImageOnErrorStrategy(prefix, useAdvancedMode),
					NewInputAutofocusOnfocusStrategy(prefix, useAdvancedMode),
				),
			),
		),
	)

	epqInstance := &GenericBreakoutCompositeStrategy{
		combinedStrategy: finalCombinedStrategy,
	}

	return epqInstance
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Epq.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *GenericBreakoutCompositeStrategy) GeneratePayload(
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
