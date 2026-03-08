package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// BasicScriptTagStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fs4
type BasicScriptTagStrategy struct {
	tagPrefix       string // Corresponds to 'a' in Java
	useAdvancedMode bool   // Corresponds to 'b' in Java
}

// NewBasicScriptTagStrategy creates a new instance of Fs4.
// Original Java constructor: public fs4(String var1, boolean var2)
func NewBasicScriptTagStrategy(prefix string, advancedMode bool) *BasicScriptTagStrategy {
	return &BasicScriptTagStrategy{
		tagPrefix:       prefix,
		useAdvancedMode: advancedMode,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *BasicScriptTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return var1.a(4).a((byte)0, "#{random_string_5}" + this.a + "<script>#{poc}</script>#{random_string_5b}", var2.a(this.b));

	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<script>#{poc}</script>#{random_string_5b}"

	// var2.a(this.b) now returns Hnx
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	// var1.a(4).BuildBgf((byte)0, payload, configuredHnx)
	return probeBuilder.WithAdditionalScanFlags(4).
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
