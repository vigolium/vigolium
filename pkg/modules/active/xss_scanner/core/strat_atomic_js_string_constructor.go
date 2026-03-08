package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JSStringFromComponentsStrategy implements the ContextualXSSTechnique interface.
// Original Java class: dff
type JSStringFromComponentsStrategy struct {
	components JSStringPayloadComponents // Corresponds to 'private final idh a;'
}

// NewJSStringFromComponentsStrategy creates a new instance of Dff.
// Original Java constructor: public dff(idh var1)
func NewJSStringFromComponentsStrategy(
	components JSStringPayloadComponents,
) *JSStringFromComponentsStrategy {
	return &JSStringFromComponentsStrategy{
		components: components,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Dff.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *JSStringFromComponentsStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic:
	// return var1.a(4)
	//    .a(
	//       (byte)3,
	//       "#{random_string_5}" + this.a.b + "#{poc}" + this.a.a + "#{random_string_5b}",  // payload1
	//       var2.b("#{random_string_5}" + this.a.c + "#{poc}" + this.a.d + "#{random_string_5b}") // hnx processing part
	//    );

	// Payload part 1 (for hgm.a)
	mainFormattedPayload := "#{random_string_5}" + receiver.components.payloadWithBaseSuffix + "#{poc}" + receiver.components.baseSuffix + "#{random_string_5b}"

	// Payload part 2 (for hnx.b)
	profilePayloadComponent := "#{random_string_5}" + receiver.components.encodedPayloadWithBaseSuffix + "#{poc}" + receiver.components.encodedBaseSuffix + "#{random_string_5b}"

	// Hnx processing: var2.b(payload2) -> profile.B(payload2) which now returns Hnx
	finalProfile := profile.WithVariantCanaryComponent(profilePayloadComponent)

	// Final assembly: var1.a(4).a((byte)3, payload1, configuredHnx)
	return probeBuilder.WithAdditionalScanFlags(4).
		BuildFinding(byte(3), mainFormattedPayload, finalProfile)
}
