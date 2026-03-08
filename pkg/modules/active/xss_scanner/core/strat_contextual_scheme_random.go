package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeWithRandomStringStrategy implements the ContextualXSSTechnique interface.
// Original Java class: cy_
type SchemeWithRandomStringStrategy struct {
	scheme        SchemeDefinition // Corresponds to 'private final dir a;'
	payloadSuffix string           // Corresponds to 'private final String b;'
}

// NewSchemeWithRandomStringStrategy creates a new instance of Cy_.
// Original Java constructor: public cy_(dir var1, String var2)
func NewSchemeWithRandomStringStrategy(
	scheme SchemeDefinition,
	suffix string,
) *SchemeWithRandomStringStrategy {
	return &SchemeWithRandomStringStrategy{
		scheme:        scheme,
		payloadSuffix: suffix,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (strategy *SchemeWithRandomStringStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var1.a(this.a.c()).a((byte)11, this.a.b() + ":" + this.b + "#{random_string_8}", var2.f());

	// this.a.b() + ":" + this.b + "#{random_string_8}"
	formattedPayload := strategy.scheme.SchemeName() + ":" + strategy.payloadSuffix + "#{random_string_8}"

	// var1.a(this.a.c()) -> probeBuilder.AVal(receiver.ValDir.C())
	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(strategy.scheme.SchemeFlag())

	// var2.f() -> profile.F()
	finalProfile := profile.WithDetectorValidation()

	// .a((byte)11, payload, processedHnx)
	return adjustedProbeBuilder.BuildFinding(byte(11), formattedPayload, finalProfile)
}
