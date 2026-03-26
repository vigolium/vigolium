package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// MultiSchemeURLCompositeStrategy corresponds to Java class hcb which extends hcu and implements d3b.
// Logic from hcu is effectively part of MultiSchemeURLCompositeStrategy's D3b implementation.
type MultiSchemeURLCompositeStrategy struct {
	randomProvider *utils.RandomGenerator // Corresponds to 'private final ou a;' in hcb
}

// NewMultiSchemeURLCompositeStrategy creates a new instance of Hcb.
// Original Java constructor: public hcb(ou var1)
func NewMultiSchemeURLCompositeStrategy(
	randomProvider *utils.RandomGenerator,
) *MultiSchemeURLCompositeStrategy {
	return &MultiSchemeURLCompositeStrategy{
		randomProvider: randomProvider,
	}
}

// --- Methods corresponding to hcu's abstract methods, implemented by hcb ---

// PreliminaryXSSFinding is the Go equivalent of hcb's override of hcu's abstract a(hgm, hnx).
// Original Java: public bgf a(hgm var1, hnx var2)
func (receiver *MultiSchemeURLCompositeStrategy) PreliminaryXSSFinding(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	// return var1.c().a((byte)11, "#{random_string_5}:#{random_string_5b}", var2.f());
	formattedPayload := "#{random_string_5}:#{random_string_5b}"
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(11), formattedPayload, profile.WithDetectorValidation())
}

// getCombinedSchemeStrategies is the Go equivalent of hcb's override of hcu's abstract a() returning d3b.
// Original Java: public d3b a()
func (receiver *MultiSchemeURLCompositeStrategy) getCombinedSchemeStrategies() ContextualAttackPayloadGenerator {
	// og var10000 = new og(
	//    new gfw(new es0(new diw("javascript")), new es0(new dix("jaVascrIpt"))),
	//    new gfw(new eb(this.a, new diw("data")), new eb(this.a, new dix("daTa"))),
	//    new gfw(new gg9(new diw("vbscript")), new gg9(new dix("vBscrIpt")))
	// );

	// Component 1 for og
	javascriptStrategy1 := NewSchemeSpecificPayloadCompositeStrategy(
		NewBasicSchemeDefinition("javascript"),
	)
	javascriptStrategy2 := NewSchemeSpecificPayloadCompositeStrategy(
		NewMixCasesSchemeDefinition("jaVascrIpt"),
	)
	javascriptIteratorStrategy := NewFirstSuccessMetaStrategy(
		javascriptStrategy1,
		javascriptStrategy2,
	)

	// Component 2 for og
	dataURISchemeStrategy1 := NewDataURISchemeCompositeStrategy(
		receiver.randomProvider,
		NewBasicSchemeDefinition("data"),
	)
	dataURISchemeStrategy2 := NewDataURISchemeCompositeStrategy(
		receiver.randomProvider,
		NewMixCasesSchemeDefinition("daTa"),
	)
	dataURIIteratorStrategy := NewFirstSuccessMetaStrategy(
		dataURISchemeStrategy1,
		dataURISchemeStrategy2,
	)

	// Component 3 for og
	vbscriptStrategy1 := NewVBScriptSchemeCompositeStrategy(NewBasicSchemeDefinition("vbscript")) // NewGg9 is ported
	vbscriptStrategy2 := NewVBScriptSchemeCompositeStrategy(NewMixCasesSchemeDefinition("vBscrIpt"))
	vbscriptIteratorStrategy := NewFirstSuccessMetaStrategy(vbscriptStrategy1, vbscriptStrategy2)

	prioritizedIterator := NewPrioritizedIteratingMetaStrategy(
		javascriptIteratorStrategy,
		dataURIIteratorStrategy,
		vbscriptIteratorStrategy,
	)

	return prioritizedIterator // ogInstance is D3b as NewOg returns D3b
}

// --- D3b interface method A, as implemented by hcu (the parent class) ---

// GeneratePayload is the Go equivalent of the d3b interface's 'a' method,
// ported from hcu.java (which hcb extends).
// Original Java from hcu:
// @Override
//
//	public bgf a(hgm var1, hnx var2, byte var3, byte var4, eqx var5, byte[] var6) {
//	   return this.a(var1, var2) == null ? null : this.a().a(var1, var2, var3, var4, var5, var6);
//	}
func (receiver *MultiSchemeURLCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Call the hcb-specific implementation of hcu's first abstract method: this.a(hgm, hnx)
	initialFinding := receiver.PreliminaryXSSFinding(probeBuilder, profile)

	if initialFinding == nil {
		return nil
	}

	// Call the hcb-specific implementation of hcu's second abstract method: this.a() returning d3b
	combinedSchemeStrategy := receiver.getCombinedSchemeStrategies()
	if combinedSchemeStrategy == nil { // Defensive check, though original doesn't show this before calling .a
		return nil
	}

	return combinedSchemeStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
