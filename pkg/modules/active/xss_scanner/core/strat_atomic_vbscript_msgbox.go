package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// VBScriptMsgboxStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fc5
type VBScriptMsgboxStrategy struct {
	delimiter string // Corresponds to 'a' in Java
}

// NewVBScriptMsgboxStrategy creates a new instance of Fc5.
// Original Java constructor: public fc5(String var1)
func NewVBScriptMsgboxStrategy(delimiter string) *VBScriptMsgboxStrategy {
	return &VBScriptMsgboxStrategy{
		delimiter: delimiter,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the d3b interface.
// Original Java method: public bgf a(hgm var1, hnx var2, byte var3, byte var4, eqx var5, byte[] var6)
func (receiver *VBScriptMsgboxStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return var1.c().a(16388).a((byte)13, "#{random_numeric_string_5}" + this.a + "&msgbox(1)&" + this.a + "#{random_numeric_string_3}", var2);

	formattedPayload := "#{random_numeric_string_5}" + receiver.delimiter + "&msgbox(1)&" + receiver.delimiter + "#{random_numeric_string_3}"

	// var1.c().a(16388).BuildBgf((byte)13, payload, var2)
	return probeBuilder.WithoutSecondaryCanary().
		WithAdditionalScanFlags(16388).
		BuildFinding(byte(13), formattedPayload, profile)
}
