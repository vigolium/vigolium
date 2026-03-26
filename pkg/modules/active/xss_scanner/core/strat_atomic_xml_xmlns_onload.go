package core

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// XMLNamespaceOnloadStrategy implements the ContextualXSSTechnique interface.
type XMLNamespaceOnloadStrategy struct {
	payloadGeneratingStrategy ContextualAttackPayloadGenerator
	contentTypeProfile        *ContentTypeProfile
}

func createXMLNamespaceOnloadPayload(
	prefix string,
	quoteChar rune,
	useAdvancedMode bool,
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	byteVal6 ReflectionTacticType,
	byteVal7 ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	bytesVal9 *utils.HTTPTransaction,
) PotentialXSSFinding {

	xmlPayloadBody := fmt.Sprintf(
		"%s<a xmlns:a=%shttp://www.w3.org/1999/xhtml%s><a:body onload=%s%s%s/></a>",
		prefix,
		string(quoteChar),
		string(quoteChar),
		string(quoteChar),
		"#{poc}",
		string(quoteChar),
	)

	finalFormattedPayload := "#{random_string_5}" + xmlPayloadBody + "#{random_string_5b}"

	finalProfile := profile.WithAdvancedMode(useAdvancedMode)
	return probeBuilder.WithAdditionalScanFlags(4).
		BuildFinding(byte(12), finalFormattedPayload, finalProfile)
}

// xmlNamespaceOnloadLambdaWrapper implements ContextualXSSTechnique and captures variables for the XML payload lambda.
type xmlNamespaceOnloadLambdaWrapper struct {
	capturedPrefix          string
	capturedQuoteChar       rune
	capturedUseAdvancedMode bool
}

func (w *xmlNamespaceOnloadLambdaWrapper) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {
	return createXMLNamespaceOnloadPayload(
		w.capturedPrefix,
		w.capturedQuoteChar,
		w.capturedUseAdvancedMode,
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}

// NewXMLNamespaceOnloadStrategy creates a new instance.
func NewXMLNamespaceOnloadStrategy(
	contentType *ContentTypeProfile,
	prefix string,
	useAdvancedMode bool,
) *XMLNamespaceOnloadStrategy {
	receiver := &XMLNamespaceOnloadStrategy{contentTypeProfile: contentType}

	quoteCharsToTry := []rune{'\'', '"'}

	strategiesForQuotes := make([]ContextualAttackPayloadGenerator, len(quoteCharsToTry))

	for index := 0; index < len(quoteCharsToTry); index++ {
		// Create a wrapper instance that captures the necessary variables.
		strategiesForQuotes[index] = &xmlNamespaceOnloadLambdaWrapper{
			capturedPrefix:          prefix,
			capturedQuoteChar:       quoteCharsToTry[index],
			capturedUseAdvancedMode: useAdvancedMode,
		}

	}

	receiver.payloadGeneratingStrategy = NewFirstSuccessMetaStrategy(strategiesForQuotes...)

	return receiver
}

func (receiver *XMLNamespaceOnloadStrategy) GeneratePayload(
	probeBuilder *ScanProbeBuilder,
	profile *ScanExecutionProfile,
	tactic ReflectionTacticType,
	contextType ReflectionContext,
	reflection ReflectionOccurrenceDetail,
	transaction *utils.HTTPTransaction,
) PotentialXSSFinding {

	// 262 is DefTypeXML (constant from stubs.go)
	if receiver.contentTypeProfile == nil || receiver.contentTypeProfile.GetStatedTypeCode() != DefTypeXML {
		return nil
	}
	return receiver.payloadGeneratingStrategy.GeneratePayload(
		probeBuilder,
		profile,
		tactic,
		contextType,
		reflection,
		transaction,
	)
}
