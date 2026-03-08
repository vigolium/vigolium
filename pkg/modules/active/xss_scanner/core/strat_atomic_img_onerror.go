package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ImageOnErrorStrategy implements the ContextualXSSTechnique interface.
// Original Java class: hpa
type ImageOnErrorStrategy struct {
	tagPrefix       string // Corresponds to 'a' in Java
	useAdvancedMode bool   // Corresponds to 'b' in Java
}

// NewImageOnErrorStrategy creates a new instance of Hpa.
// Original Java constructor: public hpa(String var1, boolean var2)
func NewImageOnErrorStrategy(prefix string, advancedMode bool) *ImageOnErrorStrategy {
	return &ImageOnErrorStrategy{
		tagPrefix:       prefix,
		useAdvancedMode: advancedMode,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the d3b interface for class Hpa.
// Original Java method: public bgf a(hgm var1, hnx var2, byte var3, byte var4, eqx var5, byte[] var6)
func (receiver *ImageOnErrorStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return var1.a(20).a((byte)1, "#{random_string_5}" + this.a + "<img src=a onerror=#{poc}>#{random_string_5b}", var2.a(this.b));

	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<img src=a onerror=#{poc}>#{random_string_5b}"

	// var2.a(this.b) now returns Hnx
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	// Call BuildBgf
	return probeBuilder.WithAdditionalScanFlags(20).
		BuildFinding(byte(1), formattedPayload, finalProfile)
}
