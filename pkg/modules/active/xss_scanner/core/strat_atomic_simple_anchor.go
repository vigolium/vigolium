package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SimpleAnchorAttributeStrategy implements the ContextualXSSTechnique interface.
// Original Java class: deb
type SimpleAnchorAttributeStrategy struct {
	tagPrefix       string // Corresponds to 'a' in Java
	useAdvancedMode bool   // Corresponds to 'b' in Java
}

// NewSimpleAnchorAttributeStrategy creates a new instance of Deb.
// Original Java constructor: public deb(String var1, boolean var2)
func NewSimpleAnchorAttributeStrategy(
	prefix string,
	advancedMode bool,
) *SimpleAnchorAttributeStrategy {
	return &SimpleAnchorAttributeStrategy{
		tagPrefix:       prefix,
		useAdvancedMode: advancedMode,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *SimpleAnchorAttributeStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// String var7 = "#{random_string_5}" + this.a + "<a b=c>#{random_string_5b}";
	// return var1.c().a((byte)1, var7, var2.a(this.b));

	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<a b=c>#{random_string_5b}"

	// var2.a(this.b) now returns Hnx
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	// var1.c().BuildBgf((byte)1, payload, configuredHnx)
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(1), formattedPayload, finalProfile)
}
