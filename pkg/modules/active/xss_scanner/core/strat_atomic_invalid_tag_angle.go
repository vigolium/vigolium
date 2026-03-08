package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// AngleBracketInvalidTagStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fft
type AngleBracketInvalidTagStrategy struct {
	useAdvancedMode bool   // Corresponds to 'b' in Java
	tagPrefix       string // Corresponds to 'a' in Java
}

// NewAngleBracketInvalidTagStrategy creates a new instance of Fft.
// Original Java constructor: public fft(boolean var1, String var2)
func NewAngleBracketInvalidTagStrategy(
	advancedMode bool,
	prefix string,
) *AngleBracketInvalidTagStrategy {
	return &AngleBracketInvalidTagStrategy{
		useAdvancedMode: advancedMode,
		tagPrefix:       prefix,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the d3b interface.
// Original Java method: public bgf a(hgm var1, hnx var2, byte var3, byte var4, eqx var5, byte[] var6)
func (receiver *AngleBracketInvalidTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var1.c().a((byte)0, this.a + "<#{random_invalid_tag_name_5}>", var2.a(this.b));
	formattedPayload := receiver.tagPrefix + "<#{random_invalid_tag_name_5}>"
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
