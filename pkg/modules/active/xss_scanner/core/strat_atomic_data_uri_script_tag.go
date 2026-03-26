package core

import (
	"encoding/base64"
	"fmt"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// DataURIBase64ScriptStrategy implements the ContextualXSSTechnique interface.
type DataURIBase64ScriptStrategy struct {
	randomProvider     *utils.RandomGenerator
	uriPrefix          string
	uriSchemeSeparator string
}

// NewDataURIBase64ScriptStrategy creates a new instance.
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

func (receiver *DataURIBase64ScriptStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	defaultTechniqueClassifier := GetDefaultAttackTechniqueClassifier()

	scriptTagPayload := fmt.Sprintf(
		"<script>%s//%s</script>",
		defaultTechniqueClassifier.String(),
		receiver.randomProvider.GeneratePrefixedAlphanumeric(8),
	)

	scriptTagBytes := utils.StringToBytes(scriptTagPayload)
	base64EncodedScript := base64.StdEncoding.EncodeToString(scriptTagBytes)

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

	finding := probeBuilder.WithAdditionalScanFlags(4).
		BuildFinding(byte(11), formattedDataURIPayload, profile.WithDetectorValidation())

	return finding
}
