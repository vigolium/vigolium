package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"

// ProcessedClosingTagStrategy implements the ContextualXSSTechnique interface.
// Original Java class: iw1
type ProcessedClosingTagStrategy struct {
	tagName            string // Corresponds to 'a' in Java
	payloadContextCode byte   // Corresponds to 'b' in Java
}

// NewProcessedClosingTagStrategy creates a new instance of Iw1.
// Original Java constructor: public iw1(String var1, byte var2)
func NewProcessedClosingTagStrategy(tagName string, contextCode byte) *ProcessedClosingTagStrategy {
	return &ProcessedClosingTagStrategy{
		tagName:            tagName,
		payloadContextCode: contextCode,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class Iw1.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *ProcessedClosingTagStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// String var7 = "#{random_string_5}</" + cqz.e(this.a) + " >#{random_string_5b}";
	mangledTagName := mangleTagNameForClosing(receiver.tagName)
	formattedPayload := "#{random_string_5}</" + mangledTagName + " >#{random_string_5b}"

	// probeBuilder.AVal(8).C().BuildBgf(byte, string, *Hnx)
	return probeBuilder.WithAdditionalScanFlags(8).
		WithoutSecondaryCanary().
		BuildFinding(receiver.payloadContextCode, formattedPayload, profile)
}
