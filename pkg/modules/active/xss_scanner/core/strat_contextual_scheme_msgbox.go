package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemeMsgboxPayloadStrategy implements the ContextualXSSTechnique interface.
// Original Java class: gdz
type SchemeMsgboxPayloadStrategy struct {
	scheme SchemeDefinition // Corresponds to 'private final dir a;'
}

// NewSchemeMsgboxPayloadStrategy creates a new instance of Gdz.
// Original Java constructor: public gdz(dir var1)
func NewSchemeMsgboxPayloadStrategy(scheme SchemeDefinition) *SchemeMsgboxPayloadStrategy {
	return &SchemeMsgboxPayloadStrategy{
		scheme: scheme,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Gdz.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (strategy *SchemeMsgboxPayloadStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return var1.a(16388 | this.a.c()).a((byte)11, this.a.b() + ":msgbox(#{random_numeric_string_8})", var2.f());

	formattedPayload := strategy.scheme.SchemeName() + ":msgbox(#{random_numeric_string_8})"

	// 16388 | this.a.c()
	combinedScanFlags := 16388 | strategy.scheme.SchemeFlag() // Bitwise OR
	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(combinedScanFlags)

	finalProfile := profile.WithDetectorValidation()

	return adjustedProbeBuilder.BuildFinding(byte(11), formattedPayload, finalProfile)
}
