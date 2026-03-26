package core

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// --- HgmImpl struct and Interface Implementation ---

// It implements the ScanProbeBuilder interface.
type ScanProbeBuilder struct {
	scanFlags                   int
	attackStepRunner            AttackStepRunner
	randomProvider              *utils.RandomGenerator
	randomStringGenerator       RandomTextProvider
	injectionPoint              httpmsg.InsertionPoint
	tacticType                  ReflectionTacticType
	techniqueClassifier         AttackTechniqueClassifier
	useSecondaryCanaryComponent bool
}

// IsScanProbeBuilder marker method for the ScanProbeBuilder interface.
func (h *ScanProbeBuilder) IsScanProbeBuilder() {}

// --- Constructors ---

// NewScanProbeBuilder is the primary public constructor.
func NewScanProbeBuilder(
	randomProvider *utils.RandomGenerator,
	randomStringGenerator RandomTextProvider,
	attackStepRunner AttackStepRunner,
	injectionPoint httpmsg.InsertionPoint,
	techniqueClassifier AttackTechniqueClassifier,
	tactic ReflectionTacticType,
	useSecondaryCanary bool,
) *ScanProbeBuilder {
	return newScanProbeBuilderInternal(
		randomProvider,
		randomStringGenerator,
		attackStepRunner,
		injectionPoint,
		techniqueClassifier,
		0,
		tactic,
		useSecondaryCanary,
	)
}

// newScanProbeBuilderInternal is the private constructor equivalent.
func newScanProbeBuilderInternal(
	randomProvider *utils.RandomGenerator,
	randomStringGenerator RandomTextProvider,
	attackStepRunner AttackStepRunner,
	injectionPoint httpmsg.InsertionPoint,
	techniqueClassifier AttackTechniqueClassifier,
	initialScanFlags int,
	tactic ReflectionTacticType,
	useSecondaryCanary bool,
) *ScanProbeBuilder {
	return &ScanProbeBuilder{
		scanFlags:                   initialScanFlags,
		attackStepRunner:            attackStepRunner,
		randomProvider:              randomProvider,
		randomStringGenerator:       randomStringGenerator,
		injectionPoint:              injectionPoint,
		tacticType:                  tactic,
		techniqueClassifier:         techniqueClassifier,
		useSecondaryCanaryComponent: useSecondaryCanary,
	}
}

// --- ScanProbeBuilder Interface Methods ---

func (builder *ScanProbeBuilder) BuildFinding(
	contextCode byte,
	payloadTemplate string,
	profile *ScanExecutionProfile,
) PotentialXSSFinding {
	templateData := builder.preparePayloadTemplateData(payloadTemplate)

	finalPayload := FormatPayloadFromTemplate(payloadTemplate, templateData)
	zap.L().Debug("BuildFinding.finalPayload", zap.String("payload", finalPayload))

	profileWithTemplateData := profile.withPayloadTemplateData(templateData)
	finalProfile := profileWithTemplateData.withBaseCanaryComponent(finalPayload)

	return builder.attackStepRunner.RunAttackStep(
		builder.injectionPoint,
		builder.scanFlags,
		finalPayload,
		builder.tacticType,
		contextCode,
		builder.techniqueClassifier,
		builder.useSecondaryCanaryComponent,
		finalProfile,
	)
}

func (builder *ScanProbeBuilder) WithAdditionalScanFlags(flags int) *ScanProbeBuilder {
	return newScanProbeBuilderInternal(
		builder.randomProvider,
		builder.randomStringGenerator,
		builder.attackStepRunner,
		builder.injectionPoint,
		builder.techniqueClassifier,
		builder.scanFlags|flags,
		builder.tacticType,
		builder.useSecondaryCanaryComponent,
	)
}

func (builder *ScanProbeBuilder) WithoutSecondaryCanary() *ScanProbeBuilder {
	return newScanProbeBuilderInternal(
		builder.randomProvider,
		builder.randomStringGenerator,
		builder.attackStepRunner,
		builder.injectionPoint,
		builder.techniqueClassifier,
		builder.scanFlags,
		builder.tacticType,
		false,
	)
}

// --- Private Instance Methods ---

func (builder *ScanProbeBuilder) preparePayloadTemplateData(
	baseFormatString string,
) *PayloadGenerationTemplate {
	randomNumericSuffix1 := "0"
	randomNumericSuffix2 := "0"
	randomNumericSuffix3 := "0"

	if builder.randomProvider != nil {
		randomNumericSuffix1 = builder.randomProvider.GetRandomNumericString(100, 1000)
		randomNumericSuffix2 = builder.randomProvider.GetRandomNumericString(10000, 100000)
		randomNumericSuffix3 = builder.randomProvider.GetRandomNumericString(10000000, 100000000)
	}

	return NewPayloadGenerationTemplate(
		builder,
		builder.techniqueClassifier,
		builder.randomProvider.GeneratePrefixedAlphanumeric(5),
		builder.randomProvider.GeneratePrefixedAlphanumeric(5),
		builder.randomProvider.GeneratePrefixedAlphanumeric(8),
		builder.randomProvider.GeneratePrefixedAlphanumeric(10),
		randomNumericSuffix1,
		randomNumericSuffix2,
		randomNumericSuffix3,
		builder.randomStringGenerator.GenerateText(5),
		baseFormatString,
	)
}

// --- Static Helper Methods for building scan probes ---

func FormatPayloadFromTemplate(template string, templateData *PayloadGenerationTemplate) string {
	if templateData == nil {
		return template
	}

	// 1. Escape all '%' characters in the original format string to prevent fmt.Sprintf misinterpretation.
	tempFormatStr := strings.ReplaceAll(template, "%", "%%")

	// 2. Define placeholders and their corresponding fmt format verbs using indexed syntax.
	replacements := map[string]string{
		"#{poc}":                       "%[1]s",
		"#{random_string_5}":           "%[2]s",
		"#{random_string_5b}":          "%[3]s",
		"#{random_string_8}":           "%[4]s",
		"#{random_string_10}":          "%[5]s",
		"#{random_numeric_string_3}":   "%[6]s",
		"#{random_numeric_string_5}":   "%[7]s",
		"#{random_numeric_string_8}":   "%[8]s",
		"#{random_invalid_tag_name_5}": "%[9]s",
	}

	// 3. Replace placeholders with fmt format verbs.
	for placeholder, fmtVerb := range replacements {
		tempFormatStr = strings.ReplaceAll(tempFormatStr, placeholder, fmtVerb)
	}

	// 4. Prepare the values for formatting.
	var techniqueClassifier string
	if templateData.techniqueClassifier != nil {
		techniqueClassifier = templateData.techniqueClassifier.String()
	}

	// 5. Call fmt.Sprintf with the processed format string and arguments (order must match indexed verbs).
	formatted := fmt.Sprintf(tempFormatStr,
		techniqueClassifier,                // arg 1 -> %[1]s
		templateData.randomString5a,        // arg 2 -> %[2]s
		templateData.randomString5b,        // arg 3 -> %[3]s
		templateData.randomString8,         // arg 4 -> %[4]s
		templateData.randomString10,        // arg 5 -> %[5]s
		templateData.randomNumericSuffix1,  // arg 6 -> %[6]s
		templateData.randomNumericSuffix2,  // arg 7 -> %[7]s
		templateData.randomNumericSuffix3,  // arg 8 -> %[8]s
		templateData.randomInvalidTagName5, // arg 9 -> %[9]s
	)

	return formatted
}

func PreparePayloadTemplateDataForBuilder(
	builder *ScanProbeBuilder,
	baseFormatString string,
) *PayloadGenerationTemplate {
	if builder != nil {
		return builder.preparePayloadTemplateData(baseFormatString)
	}
	return nil
}
