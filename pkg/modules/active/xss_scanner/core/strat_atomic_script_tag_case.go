package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// CaseVariantScriptTagStrategy implements the ContextualXSSTechnique interface.
// Original Java class: bfn
type CaseVariantScriptTagStrategy struct {
	tagPrefix       string // Corresponds to 'b' in Java
	useAdvancedMode bool   // Corresponds to 'a' in Java
}

// NewCaseVariantScriptTagStrategy creates a new instance of Bfn.
// Original Java constructor: public bfn(String var1, boolean var2)
func NewCaseVariantScriptTagStrategy(
	prefix string,
	advancedMode bool,
) *CaseVariantScriptTagStrategy {
	return &CaseVariantScriptTagStrategy{
		tagPrefix:       prefix,
		useAdvancedMode: advancedMode,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *CaseVariantScriptTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return var1.a(12).a((byte)0, "#{random_string_5}" + this.b + "<ScRiPt>#{poc}</ScRiPt>#{random_string_5b}", var2.a(this.a));

	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<ScRiPt>#{poc}</ScRiPt>#{random_string_5b}"

	// var2.a(this.a) now returns Hnx
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	// Call BuildBgf
	return probeBuilder.WithAdditionalScanFlags(12).
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
