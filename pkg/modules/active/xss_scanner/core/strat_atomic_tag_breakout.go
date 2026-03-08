package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// TagBreakoutStrategy implements the ContextualXSSTechnique interface.
// Original Java class: b3d
type TagBreakoutStrategy struct {
	useAdvancedMode bool   // Corresponds to 'b' in Java
	tagPrefix       string // Corresponds to 'a' in Java
}

// NewTagBreakoutStrategy creates a new instance of B3d.
// Original Java constructor: public b3d(boolean var1, String var2)
func NewTagBreakoutStrategy(advancedMode bool, prefix string) *TagBreakoutStrategy {
	return &TagBreakoutStrategy{
		useAdvancedMode: advancedMode,
		tagPrefix:       prefix,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *TagBreakoutStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var1.c().a((byte)0, "#{random_string_10}" + this.a + "><", var2.a(this.b));
	formattedPayload := "#{random_string_10}" + receiver.tagPrefix + "><"

	// var2.a(this.b) now returns Hnx
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
