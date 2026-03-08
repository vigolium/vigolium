package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// Import for string formatting if needed, though not directly for this one yet

// NullByteInTagStrategy implements the ContextualXSSTechnique interface.
// Original Java class: a6o
type NullByteInTagStrategy struct {
	useAdvancedMode bool   // Corresponds to 'a' in Java
	tagPrefix       string // Corresponds to 'b' in Java
}

// NewNullByteInTagStrategy creates a new instance of A6o.
// Original Java constructor: public a6o(boolean var1, String var2)
func NewNullByteInTagStrategy(advancedMode bool, prefix string) *NullByteInTagStrategy {
	return &NullByteInTagStrategy{
		useAdvancedMode: advancedMode,
		tagPrefix:       prefix,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *NullByteInTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var1.c().a(32768).a((byte)0, this.b + "<\u0000#{random_invalid_tag_name_5}>", var2.a(this.a));
	formattedPayload := receiver.tagPrefix + "<\x00#{random_invalid_tag_name_5}>"

	// var2.a(this.a) now returns Hnx
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)

	// Call BuildBgf on Hgm
	return probeBuilder.WithoutSecondaryCanary().
		WithAdditionalScanFlags(32768).
		BuildFinding(byte(0), formattedPayload, finalProfile)
}
