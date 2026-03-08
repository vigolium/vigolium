package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// SimpleAnchorTagStrategy implements the ContextualXSSTechnique interface.
// Original Java class: b0q
type SimpleAnchorTagStrategy struct {
	tagPrefix string // Corresponds to 'a' in Java
}

// NewSimpleAnchorTagStrategy creates a new instance of B0q.
// Original Java constructor: public b0q(String var1)
func NewSimpleAnchorTagStrategy(prefix string) *SimpleAnchorTagStrategy {
	return &SimpleAnchorTagStrategy{
		tagPrefix: prefix,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *SimpleAnchorTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// Original Java logic: return var1.c().a((byte)0, "#{random_string_5}" + this.a + "<a>#{random_string_5b}", var2);
	formattedPayload := "#{random_string_5}" + receiver.tagPrefix + "<a>#{random_string_5b}"
	return probeBuilder.WithoutSecondaryCanary().BuildFinding(byte(0), formattedPayload, profile)
}
