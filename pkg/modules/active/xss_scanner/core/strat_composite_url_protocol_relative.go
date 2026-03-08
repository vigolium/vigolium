package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// URLProtocolRelativeCompositeStrategy corresponds to Java class hcv which extends hcu and implements ContextualXSSTechnique.
// Logic from hcu is effectively part of URLProtocolRelativeCompositeStrategy's ContextualXSSTechnique implementation.
type URLProtocolRelativeCompositeStrategy struct{}

// NewURLProtocolRelativeCompositeStrategy creates a new instance of Hcv.
// Original Java constructor: (default, as hcv has no explicit constructor)
func NewURLProtocolRelativeCompositeStrategy() *URLProtocolRelativeCompositeStrategy {
	return &URLProtocolRelativeCompositeStrategy{}
}

// --- Methods corresponding to hcu's abstract methods, implemented by hcv ---

// A_HgmHnx is the Go equivalent of hcv's override of hcu's abstract a(hgm, hnx).
// Original Java: public PreliminaryXSSFinding a(hgm var1, hnx var2)
func (receiver *URLProtocolRelativeCompositeStrategy) A_HgmHnx(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	// return var1.c().a((byte)11, "#{random_string_5}://#{random_string_5b}", var2.f());
	formattedPayload := "#{random_string_5}://#{random_string_5b}"
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(11), formattedPayload, profile.WithDetectorValidation())
}

// getCombinedProtocolRelativeStrategies is the Go equivalent of hcv's override of hcu's abstract a() returning ContextualXSSTechnique.
// Original Java: public ContextualXSSTechnique a()
func (receiver *URLProtocolRelativeCompositeStrategy) getCombinedProtocolRelativeStrategies() ContextualAttackPayloadGenerator {
	// return new gfw(new ew8(new diw("javascript")), new ew8(new dix("jaVascrIpt")));
	javascriptSchemeStrategy := NewSchemeWithNewlineCompositeStrategy(
		NewBasicSchemeDefinition("javascript"),
	)
	obfuscatedJSSchemeStrategy := NewSchemeWithNewlineCompositeStrategy(
		NewMixCasesSchemeDefinition("jaVascrIpt"),
	)
	iteratorStrategy := NewFirstSuccessMetaStrategy(
		javascriptSchemeStrategy,
		obfuscatedJSSchemeStrategy,
	) // NewGfw is stubbed
	return iteratorStrategy
}

// --- ContextualXSSTechnique interface method A, as implemented by hcu (the parent class) ---

// GeneratePayload is the Go equivalent of the ContextualXSSTechnique interface's 'a' method,
// ported from hcu.java (which hcv extends).
func (receiver *URLProtocolRelativeCompositeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	initialFinding := receiver.A_HgmHnx(probeBuilder, profile)
	if initialFinding == nil {
		return nil
	}
	combinedStrategy := receiver.getCombinedProtocolRelativeStrategies()
	if combinedStrategy == nil {
		return nil
	}
	return combinedStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
