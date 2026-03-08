package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// InvalidDoubleAngleTagStrategy implements the ContextualXSSTechnique interface.
// Original Java class: gem
type InvalidDoubleAngleTagStrategy struct {
	useAdvancedMode bool   // Corresponds to 'b' in Java
	tagPrefix       string // Corresponds to 'a' in Java
}

// NewInvalidDoubleAngleTagStrategy creates a new instance of Gem.
// Original Java constructor: public gem(boolean var1, String var2)
func NewInvalidDoubleAngleTagStrategy(
	useAdvancedMode bool,
	tagPrefix string,
) *InvalidDoubleAngleTagStrategy {
	return &InvalidDoubleAngleTagStrategy{
		useAdvancedMode: useAdvancedMode,
		tagPrefix:       tagPrefix,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *InvalidDoubleAngleTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var1.c().a((byte)0, this.a + "<#{random_invalid_tag_name_5}<", var2.a(this.b));
	formattedPayload := receiver.tagPrefix + "<#{random_invalid_tag_name_5}<"
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
