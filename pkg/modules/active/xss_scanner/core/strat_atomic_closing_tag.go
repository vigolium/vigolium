package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ClosingTagStrategy implements the ContextualXSSTechnique interface.
// Original Java class: eko
type ClosingTagStrategy struct {
	tagName            string // Corresponds to 'b' (String) in Java
	payloadContextCode byte   // Corresponds to 'a' (byte) in Java
}

// NewClosingTagStrategy creates a new instance of Eko.
// Original Java constructor: public eko(String var1, byte var2)
func NewClosingTagStrategy(tagName string, contextCode byte) *ClosingTagStrategy {
	return &ClosingTagStrategy{
		tagName:            tagName,
		payloadContextCode: contextCode,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Eko.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *ClosingTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// String var7 = "</" + this.b + ">";
	closingTagString := "</" + receiver.tagName + ">"

	// String var8 = "#{random_string_5}" + var7 + "#{random_string_5b}";
	formattedPayload := "#{random_string_5}" + closingTagString + "#{random_string_5b}"

	// This maps to Hgm.C().BuildBgf(byte, string, *Hnx)
	return probeBuilder.WithoutSecondaryCanary().
		BuildFinding(receiver.payloadContextCode, formattedPayload, profile)
}
