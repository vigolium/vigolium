package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// VBScriptAttributeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: htc
type VBScriptAttributeStrategy struct {
	// No fields, no explicit constructor in Java
}

// NewVBScriptAttributeStrategy creates a new instance of Htc.
func NewVBScriptAttributeStrategy() *VBScriptAttributeStrategy {
	return &VBScriptAttributeStrategy{}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Htc.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *VBScriptAttributeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// fcp var7 = (fcp)var5;
	attributeReflection, isCorrectType := reflection.(*HTMLAttributeReflection)

	// if (var7 == null) { net.portswigger.qe.a(false, net.portswigger.rg.e); return null; }
	if !isCorrectType || attributeReflection == nil {
		// net.portswigger.qe.a is ignored
		return nil
	}

	// else if (!var7.e.toLowerCase().startsWith("vbscript:")) { return null; }
	if !strings.HasPrefix(strings.ToLower(attributeReflection.attributeValue), "vbscript:") {
		return nil
	}

	// else { ... }
	// byte var8 = eba.b(var6, var7.a().f, var7.a().c);
	coreReflectionInfo := attributeReflection.CoreInfo() // fcpVal is Fcp, which embeds DetectedReflection, so it has A() returning Hpo
	if coreReflectionInfo == nil {                       // Defensive nil check for Hpo
		return nil
	}
	analyzedContextCode := GetByteContextAfterDecoding(
		transaction.GetResponseBody(),
		coreReflectionInfo.GetStartIndex(),
		coreReflectionInfo.GetEndIndex(),
	)

	// return new esm().a((byte)0, new fc5("\"")).a((byte)2, new fc5("")).a().a(var8, var1, var2, var3, var4, var5, var6);
	mappedStrategyBuilder := NewMappedStrategyBuilder()                // Stubbed
	vbscriptMsgboxWithQuoteStrategy := NewVBScriptMsgboxStrategy("\"") // Ported
	vbscriptMsgboxNoQuoteStrategy := NewVBScriptMsgboxStrategy("")     // Ported

	mappedExecutor := mappedStrategyBuilder.AddStrategy(byte(0), vbscriptMsgboxWithQuoteStrategy).
		AddStrategy(byte(2), vbscriptMsgboxNoQuoteStrategy).
		Build()

	// Call Hyt.A method. Note: Java passes var2 (hnxVal) directly.
	return mappedExecutor.ExecuteStrategyByCode(
		analyzedContextCode,
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
