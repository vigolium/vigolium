package core

// It's used as a data holder for string components, often for payload generation.
type PayloadGenerationTemplate struct {
	techniqueClassifier       AttackTechniqueClassifier
	randomString5a            string
	randomString5b            string
	randomString8             string
	randomString10            string
	randomNumericSuffix1      string
	randomNumericSuffix2      string
	randomNumericSuffix3      string
	randomInvalidTagName5     string
	primaryFormattedPayload   string
	secondaryFormattedPayload string
	probeBuilder              *ScanProbeBuilder
}

// NewPayloadGenerationTemplate creates a new instance.
func NewPayloadGenerationTemplate(
	probeBuilder *ScanProbeBuilder,
	techniqueClassifier AttackTechniqueClassifier,
	rStr5a string,
	rStr5b string,
	rStr8 string,
	rStr10 string,
	rNumSuffix1 string,
	rNumSuffix2 string,
	rNumSuffix3 string,
	rInvalidTag5 string,
	baseFormatString string,
) *PayloadGenerationTemplate {
	template := &PayloadGenerationTemplate{}

	template.probeBuilder = probeBuilder
	template.techniqueClassifier = techniqueClassifier
	template.randomString5a = rStr5a
	template.randomString5b = rStr5b
	template.randomString8 = rStr8
	template.randomString10 = rStr10
	template.randomNumericSuffix1 = rNumSuffix1
	template.randomNumericSuffix2 = rNumSuffix2
	template.randomNumericSuffix3 = rNumSuffix3
	template.randomInvalidTagName5 = rInvalidTag5

	if baseFormatString != "" {
		intermediateTemplateData := PreparePayloadTemplateDataForBuilder(
			probeBuilder,
			"",
		)

		template.primaryFormattedPayload = FormatPayloadFromTemplate(
			baseFormatString,
			intermediateTemplateData,
		)
		template.secondaryFormattedPayload = FormatPayloadFromTemplate(
			baseFormatString,
			intermediateTemplateData,
		)

	} else {
		template.primaryFormattedPayload = ""
		template.secondaryFormattedPayload = ""
	}

	return template
}
