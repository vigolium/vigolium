package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeWithPocAndRandomStringStrategy implements the ContextualXSSTechnique interface.
// Original Java class: nm
type SchemeWithPocAndRandomStringStrategy struct {
	scheme        SchemeDefinition // Corresponds to 'b' in Java
	payloadSuffix string           // Corresponds to 'a' in Java
}

// NewSchemeWithPocAndRandomStringStrategy creates a new instance of Nm.
// Original Java constructor: public nm(dir var1, String var2)
func NewSchemeWithPocAndRandomStringStrategy(
	scheme SchemeDefinition,
	suffix string,
) *SchemeWithPocAndRandomStringStrategy {
	return &SchemeWithPocAndRandomStringStrategy{
		scheme:        scheme,
		payloadSuffix: suffix,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Nm.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (strategy *SchemeWithPocAndRandomStringStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return var1.a(4 | this.b.c()).a((byte)11, this.b.b() + ":" + this.a + "#{poc}//#{random_string_8}", var2.f());

	formattedPayload := strategy.scheme.SchemeName() + ":" + strategy.payloadSuffix + "#{poc}//#{random_string_8}"

	// 4 | this.b.c()
	combinedScanFlags := 4 | strategy.scheme.SchemeFlag() // Bitwise OR
	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(combinedScanFlags)

	finalProfile := profile.WithDetectorValidation() // This returns Hnx

	return adjustedProbeBuilder.BuildFinding(
		byte(11),
		formattedPayload,
		finalProfile,
	)
}
