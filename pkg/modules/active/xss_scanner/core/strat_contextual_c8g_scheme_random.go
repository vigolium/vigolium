package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeWithRandomStringAdvancedStrategy implements the ContextualXSSTechnique interface.
// Original Java class: c8g
type SchemeWithRandomStringAdvancedStrategy struct {
	scheme SchemeDefinition // Corresponds to 'private final dir a;'
}

// NewSchemeWithRandomStringAdvancedStrategy creates a new instance of C8g.
// Original Java constructor: public c8g(dir var1)
func NewSchemeWithRandomStringAdvancedStrategy(
	scheme SchemeDefinition,
) *SchemeWithRandomStringAdvancedStrategy {
	return &SchemeWithRandomStringAdvancedStrategy{
		scheme: scheme,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *SchemeWithRandomStringAdvancedStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var1.a(this.a.c()).a((byte)11, this.a.b() + ":#{random_string_8}", var2.f());

	// this.a.b() + ":#{random_string_8}"
	formattedPayload := receiver.scheme.SchemeName() + ":#{random_string_8}"

	// var1.a(this.a.c()) -> probeBuilder.AVal(receiver.ValDir.C())
	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(receiver.scheme.SchemeFlag())

	// var2.f() -> profile.F()
	finalProfile := profile.WithDetectorValidation()

	// .a((byte)11, payload, processedHnx)
	// This matches BuildBgf(byteVal byte, strVal string, configuredHnx *Hnx) PreliminaryXSSFinding
	return adjustedProbeBuilder.BuildFinding(byte(11), formattedPayload, finalProfile)
}
