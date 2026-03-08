package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SchemePrefixSuffixRandomPayloadStrategy implements the ContextualXSSTechnique interface.
// Original Java class: fxo
type SchemePrefixSuffixRandomPayloadStrategy struct {
	payloadPrefix string           // Corresponds to 'b' (constructor var1)
	scheme        SchemeDefinition // Corresponds to 'a' (constructor var2)
	payloadSuffix string           // Corresponds to 'c' (constructor var3)
}

// NewSchemePrefixSuffixRandomPayloadStrategy creates a new instance of Fxo.
// Original Java constructor: public fxo(String var1, dir var2, String var3)
func NewSchemePrefixSuffixRandomPayloadStrategy(
	prefix string,
	scheme SchemeDefinition,
	suffix string,
) *SchemePrefixSuffixRandomPayloadStrategy {
	return &SchemePrefixSuffixRandomPayloadStrategy{
		payloadPrefix: prefix,
		scheme:        scheme,
		payloadSuffix: suffix,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Fxo.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (strategy *SchemePrefixSuffixRandomPayloadStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return var1.a(this.a.c()).a((byte)11, this.b + this.a.b() + this.c + ":#{random_string_8}", var2.f());

	formattedPayload := strategy.payloadPrefix + strategy.scheme.SchemeName() + strategy.payloadSuffix + ":#{random_string_8}"

	adjustedProbeBuilder := probeBuilder.WithAdditionalScanFlags(strategy.scheme.SchemeFlag())
	finalProfile := profile.WithDetectorValidation()

	return adjustedProbeBuilder.BuildFinding(byte(11), formattedPayload, finalProfile)
}
