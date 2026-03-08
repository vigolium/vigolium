package core

import (
	"encoding/base64"
	"fmt"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// DataURIBase64ScriptStrategy implements the ContextualXSSTechnique interface.
// Original Java class: e2b
type DataURIBase64ScriptStrategy struct {
	randomProvider     *utils.RandomGenerator // Corresponds to 'a' (net.portswigger.ou) in Java
	uriPrefix          string                 // Corresponds to 'b' (String) in Java
	uriSchemeSeparator string                 // Corresponds to 'c' (String) in Java
}

// NewDataURIBase64ScriptStrategy creates a new instance of E2b.
func NewDataURIBase64ScriptStrategy(
	randomProvider *utils.RandomGenerator,
	prefix string,
	schemeSeparator string,
) *DataURIBase64ScriptStrategy {
	return &DataURIBase64ScriptStrategy{
		randomProvider:     randomProvider,
		uriPrefix:          prefix,
		uriSchemeSeparator: schemeSeparator,
	}
}

// GeneratePayload is the Go equivalent of the 'a' method from the ContextualXSSTechnique interface for class E2b.
// Original Java method: public PreliminaryXSSFinding a(hgm var1, hnx var2, byte var3, byte var4, DetectedReflection var5, byte[] var6)
func (receiver *DataURIBase64ScriptStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	// int[] var7 = g4h.b(); // Static call, result not directly used in payload construction

	// cgv var8 = fn0.a(); // Static call
	defaultTechniqueClassifier := GetDefaultAttackTechniqueClassifier()

	// String.format("<script>%s//%s</script>", var8, this.a.a(8))
	// this.a.a(8) -> receiver.ValOuA.A(8)
	// var8 (cgv type) -> cgvVar8.ToString() (assuming cgv has a suitable string method)
	scriptTagPayload := fmt.Sprintf(
		"<script>%s//%s</script>",
		defaultTechniqueClassifier.String(),
		receiver.randomProvider.GeneratePrefixedAlphanumeric(8),
	)

	// net.portswigger.h9.a(String) -> NetPortswiggerH9AStringToBytes
	scriptTagBytes := utils.StringToBytes(scriptTagPayload)

	// net.portswigger.kh.b(byte[]) -> NetPortswiggerKhB (Base64 encode)
	base64EncodedScript := base64.StdEncoding.EncodeToString(scriptTagBytes)

	// net.portswigger.h9.a(byte[]) -> NetPortswiggerH9ABytesToString
	// base64Script := utils.NetPortswiggerH9ABytesToString(encodedBytes)

	// String.format("%sdata%s:text/html;base64,%s", this.b, this.c, base64Script)
	formattedDataURIPayload := fmt.Sprintf(
		"%sdata%s:text/html;base64,%s",
		receiver.uriPrefix,
		receiver.uriSchemeSeparator,
		base64EncodedScript,
	)
	zap.L().Debug("DataURIBase64ScriptStrategy payload",
		zap.String("uriPrefix", receiver.uriPrefix),
		zap.String("uriSchemeSeparator", receiver.uriSchemeSeparator),
		zap.String("base64EncodedScript", base64EncodedScript))

	// var1.a(4).a((byte)11, finalPayload, var2.f())
	finding := probeBuilder.WithAdditionalScanFlags(4).
		BuildFinding(byte(11), formattedDataURIPayload, profile.WithDetectorValidation())

	return finding
}
