package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// InputAutofocusOnfocusStrategy implements the ContextualXSSTechnique interface.
// Original Java class: f_6 (renamed to InputAutofocusOnfocusStrategy for Go convention)
type InputAutofocusOnfocusStrategy struct {
	tagPrefix       string // Corresponds to 'b' in Java
	useAdvancedMode bool   // Corresponds to 'a' in Java
}

// NewInputAutofocusOnfocusStrategy creates a new instance of F6.
// Original Java constructor: public f_6(String var1, boolean var2)
func NewInputAutofocusOnfocusStrategy(
	prefix string,
	advancedMode bool,
) *InputAutofocusOnfocusStrategy {
	return &InputAutofocusOnfocusStrategy{
		tagPrefix:       prefix,
		useAdvancedMode: advancedMode,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *InputAutofocusOnfocusStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// String var7 = "#{random_string_5}" + this.b + "<input type=text autofocus onfocus=#{poc}//#{random_string_5b}";
	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<input type=text autofocus onfocus=#{poc}//#{random_string_5b}"

	// return var1.a(36).a((byte)1, var7, var2.a(this.a));
	finalProfile := profile.WithAdvancedMode(receiver.useAdvancedMode)
	return probeBuilder.WithAdditionalScanFlags(36).
		BuildFinding(byte(1), formattedPayload, finalProfile)
}
