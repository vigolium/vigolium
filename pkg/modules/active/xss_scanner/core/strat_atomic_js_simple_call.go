package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// JavaScriptSimpleCallStrategy implements the D3b interface.
// Original Java class: es9
type JavaScriptSimpleCallStrategy struct {
	// No fields in the original Java class
}

// NewJavaScriptSimpleCallStrategy creates a new instance of Es9.
// Original Java class does not have an explicit constructor shown, implies default constructor.
func NewJavaScriptSimpleCallStrategy() *JavaScriptSimpleCallStrategy {
	return &JavaScriptSimpleCallStrategy{}
}

// GeneratePayload is the Go equivalent of the 'a' method from the d3b interface.
// Original Java method: public bgf a(hgm var1, hnx var2, byte var3, byte var4, eqx var5, byte[] var6)
func (receiver *JavaScriptSimpleCallStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var1.c().a((byte)3, "#{random_string_5}(a)#{random_string_5b}", var2);
	formattedPayload := "#{random_string_5}(a)#{random_string_5b}"
	return probeBuilder.WithoutSecondaryCanary().BuildFinding(byte(3), formattedPayload, profile)
}
