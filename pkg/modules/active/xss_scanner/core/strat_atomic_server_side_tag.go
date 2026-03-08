package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ServerSideTagSyntaxStrategy implements the ContextualXSSTechnique interface.
// Original Java class: dxe
type ServerSideTagSyntaxStrategy struct {
	useAdvancedMode bool   // Corresponds to 'b' in Java
	tagPrefix       string // Corresponds to 'a' in Java
}

// NewServerSideTagSyntaxStrategy creates a new instance of Dxe.
// Original Java constructor: public dxe(boolean var1, String var2)
func NewServerSideTagSyntaxStrategy(advancedMode bool, prefix string) *ServerSideTagSyntaxStrategy {
	return &ServerSideTagSyntaxStrategy{
		useAdvancedMode: advancedMode,
		tagPrefix:       prefix,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *ServerSideTagSyntaxStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return var1.a(32768).c().a((byte)0, this.a + "<%#{random_invalid_tag_name_5}>", var2.a(this.b));

	formattedPayload := receiver.tagPrefix + "<%#{random_invalid_tag_name_5}>"

	// var2.a(this.b) now returns Hnx
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	// Chained call: var1.a(32768).c().BuildBgf(...)
	return probeBuilder.WithAdditionalScanFlags(32768).
		WithoutSecondaryCanary().
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
