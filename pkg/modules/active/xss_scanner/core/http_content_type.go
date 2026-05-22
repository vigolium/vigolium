package core

import (
	"net/http" // Required for allHeaders http.Header
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/mimetype_detector"
)

const (
	DefTypeNone                int16 = 0
	DefTypeUnrecognizedContent int16 = 1
	DefTypeAmbiguous           int16 = 2
	DefTypeHTML                int16 = 256
	DefTypePlainText           int16 = 257
	DefTypeCSS                 int16 = 258
	DefTypeScript              int16 = 259
	DefTypeXML                 int16 = 262
	DefTypeJSON                int16 = 260
	DefTypeRTF                 int16 = 261
	DefTypeYAML                int16 = 263
	DefTypeUnknownImage        int16 = 512
	DefTypeJPEGImage           int16 = 513
	DefTypeGIFImage            int16 = 514
	DefTypePNGImage            int16 = 515
	DefTypeBMPImage            int16 = 516
	DefTypeTIFFImage           int16 = 517
	DefTypeSVGImage            int16 = 518
	DefTypeSound               int16 = 768
	DefTypeVideo               int16 = 769
	DefTypeUnknownApplication  int16 = 1025
	DefTypeFlashObject         int16 = 1026
	DefTypeEmptyType1280       int16 = 1280
)

type ContentTypeProfile struct {
	statedTypeCode                 int16 // This will store the effective stated type
	inferredTypeCode               int16
	isNoSniff                      bool
	isContentDispositionAttachment bool
	xContentTypeOptionsHeaderValue string
	detectedCharset                string
	rawContentTypeHeaderValue      string // Store the original Content-Type header strings that led to statedTypeCode
}

// isTextualForEffectiveness reports whether typeCode is one of the "textual"
// types consulted by determineEffectiveStatedType when deciding whether to trust
// the stated content-type over the body-inferred one. HTML is deliberately
// excluded so a stated-HTML response always yields to the body-inferred type,
// mirroring the upstream effective-type precedence this logic was ported from.
func isTextualForEffectiveness(typeCode int16) bool {
	return typeCode == DefTypePlainText || typeCode == DefTypeScript || typeCode == DefTypeCSS
}

// determineEffectiveStatedType implements logic similar to private static short ea5.a(short stated, short inferred)
func determineEffectiveStatedType(statedFromHeader int16, inferredFromBody int16) int16 {
	if !isTextualForEffectiveness(statedFromHeader) {
		return inferredFromBody
	} else {
		if !isTextualForEffectiveness(inferredFromBody) {
			return inferredFromBody
		} else {
			return statedFromHeader
		}
	}
}

func newContentTypeProfile(
	statedType int16, // This will be the effective stated type
	inferredType int16,
	contentTypeHeader string,
	isNoSniff bool,
	isAttachment bool,
	xContentTypeOptionsHeaders string,
	charsets string,
) *ContentTypeProfile {

	return &ContentTypeProfile{
		statedTypeCode:                 statedType,
		inferredTypeCode:               inferredType,
		rawContentTypeHeaderValue:      contentTypeHeader,
		isNoSniff:                      isNoSniff,
		isContentDispositionAttachment: isAttachment,
		xContentTypeOptionsHeaderValue: xContentTypeOptionsHeaders,
		detectedCharset:                charsets,
	}
}

// NewContentTypeProfile creates a new ContentTypeProfile by analyzing HTTP headers and body.
func NewContentTypeProfile(
	responseHeaders http.Header, // All response headers (resp.Header)
	responseBody []byte,
) *ContentTypeProfile {

	rawContentTypeValue := responseHeaders.Get("Content-Type")
	_, statedMimeTypeFromHeader := mimetype_detector.GetStatedInferredContentType(rawContentTypeValue)
	statedShortFromHeader := ContentTypeToDefCode(statedMimeTypeFromHeader)
	extractedCharset := mimetype_detector.ExtractCharset(rawContentTypeValue)

	headersForSniffing := make(map[string]string)
	for k, v := range responseHeaders {
		if len(v) > 0 {
			headersForSniffing[k] = v[0]
		}
	}
	noSniff := mimetype_detector.ParseIsNoSniff(headersForSniffing)
	isAttachmentDisposition := mimetype_detector.ParseIsAttachment(headersForSniffing)

	xContentTypeOptionsValue := responseHeaders.Get("X-Content-Type-Options")

	inferredMimeTypeFromBody := mimetype_detector.GetInferredContentType(responseBody)
	inferredShortFromBody := ContentTypeToDefCode(inferredMimeTypeFromBody)

	// Determine the effective stated type
	effectiveStatedShort := determineEffectiveStatedType(
		statedShortFromHeader,
		inferredShortFromBody,
	)

	return newContentTypeProfile(
		effectiveStatedShort,  // Pass the effective stated type
		inferredShortFromBody, // Pass the inferred type as is
		rawContentTypeValue,
		noSniff,
		isAttachmentDisposition,
		xContentTypeOptionsValue,
		extractedCharset,
	)
}

// IsContentTypeProfile is a marker method to satisfy the old Def interface.
func (d *ContentTypeProfile) IsContentTypeProfile() bool {
	return true
}

// GetStatedTypeCode returns the stated type code.
func (d *ContentTypeProfile) GetStatedTypeCode() int16 {
	return d.statedTypeCode
}

// GetInferredTypeCode returns the inferred type code.
func (d *ContentTypeProfile) GetInferredTypeCode() int16 {
	return d.inferredTypeCode
}

func (d *ContentTypeProfile) DetectedCharset() string {
	return d.detectedCharset
}

func (d *ContentTypeProfile) String() string {
	var sb strings.Builder
	sb.WriteString("stated type: ")
	sb.WriteString(ContentTypeCodeToString(d.statedTypeCode))
	sb.WriteString(" | inferred type: ")
	sb.WriteString(ContentTypeCodeToString(d.inferredTypeCode))

	sb.WriteString(" | raw content type: ")
	sb.WriteString(d.rawContentTypeHeaderValue)

	sb.WriteString(" | x content type options: ")
	sb.WriteString(d.xContentTypeOptionsHeaderValue)

	sb.WriteString(" | detected charset: ")
	sb.WriteString(d.detectedCharset)

	return sb.String()
}

func IsTextualContentType(contentTypeCode int16) bool {
	switch contentTypeCode {
	case DefTypeNone,
		DefTypeHTML,
		DefTypePlainText,
		DefTypeCSS,
		DefTypeScript,
		DefTypeJSON,
		DefTypeRTF,
		DefTypeXML,
		DefTypeYAML:
		return true
	case DefTypeUnrecognizedContent, DefTypeAmbiguous,
		DefTypeUnknownImage, DefTypeJPEGImage, DefTypeGIFImage, DefTypePNGImage, DefTypeBMPImage, DefTypeTIFFImage, DefTypeSVGImage,
		DefTypeSound, DefTypeVideo,
		DefTypeUnknownApplication, DefTypeFlashObject, DefTypeEmptyType1280:
		return false
	default:
		return false
	}
}

func IsAmbiguousOrUnrecognized(contentTypeCode int16) bool {
	switch contentTypeCode {
	case DefTypeNone, DefTypeUnrecognizedContent, DefTypeAmbiguous:
		return true
	default:
		return false
	}
}

func IsBinaryContentType(contentTypeCode int16) bool {
	switch contentTypeCode {
	case DefTypeNone, DefTypeUnrecognizedContent, DefTypeAmbiguous,
		DefTypeHTML, DefTypePlainText, DefTypeCSS, DefTypeScript, DefTypeJSON, DefTypeRTF, DefTypeXML, DefTypeYAML,
		DefTypeUnknownApplication, DefTypeEmptyType1280:
		return false
	case DefTypeUnknownImage,
		DefTypeJPEGImage,
		DefTypeGIFImage,
		DefTypePNGImage,
		DefTypeBMPImage,
		DefTypeTIFFImage,
		DefTypeSVGImage,
		DefTypeSound,
		DefTypeVideo,
		DefTypeFlashObject:
		return true
	default:
		return false
	}
}

func ContentTypeCodeToString(contentTypeCode int16) string {
	switch contentTypeCode {
	case DefTypeNone:
		return "none"
	case DefTypeUnrecognizedContent:
		return "unrecognized content"
	case DefTypeAmbiguous:
		return "ambiguous"
	case DefTypeHTML:
		return "HTML"
	case DefTypePlainText:
		return "plain text"
	case DefTypeCSS:
		return "CSS"
	case DefTypeScript:
		return "script"
	case DefTypeJSON:
		return "JSON"
	case DefTypeRTF:
		return "RTF"
	case DefTypeXML:
		return "XML"
	case DefTypeYAML:
		return "YAML"
	case DefTypeUnknownImage:
		return "an unknown image type"
	case DefTypeJPEGImage:
		return "a JPEG image"
	case DefTypeGIFImage:
		return "a GIF image"
	case DefTypePNGImage:
		return "a PNG image"
	case DefTypeBMPImage:
		return "a BMP image"
	case DefTypeTIFFImage:
		return "a TIFF image"
	case DefTypeSVGImage:
		return "a SVG image"
	case DefTypeSound:
		return "sound"
	case DefTypeVideo:
		return "video"
	case DefTypeUnknownApplication:
		return "an unknown application type"
	case DefTypeFlashObject:
		return "a flash object"
	case DefTypeEmptyType1280:
		return ""
	default:
		return "unrecognized"
	}
}

func ContentTypeCodeToShortString(contentTypeCode int16) string {
	switch contentTypeCode {
	case DefTypeNone, DefTypeUnrecognizedContent, DefTypeAmbiguous, DefTypeEmptyType1280:
		return ""
	case DefTypeHTML:
		return "HTML"
	case DefTypePlainText:
		return "text"
	case DefTypeCSS:
		return "CSS"
	case DefTypeScript:
		return "script"
	case DefTypeJSON:
		return "JSON"
	case DefTypeRTF:
		return "RTF"
	case DefTypeXML:
		return "XML"
	case DefTypeYAML:
		return "YAML"
	case DefTypeUnknownImage:
		return "image"
	case DefTypeJPEGImage:
		return "JPEG"
	case DefTypeGIFImage:
		return "GIF"
	case DefTypePNGImage:
		return "PNG"
	case DefTypeBMPImage:
		return "BMP"
	case DefTypeTIFFImage:
		return "TIFF"
	case DefTypeSVGImage:
		return "SVG"
	case DefTypeSound:
		return "sound"
	case DefTypeVideo:
		return "video"
	case DefTypeUnknownApplication:
		return "app"
	case DefTypeFlashObject:
		return "flash"
	default:
		return ""
	}
}

func (d *ContentTypeProfile) GetContentTypeHeaderValue() string {
	return d.rawContentTypeHeaderValue
}

func stripContentTypeParameters(headerValuePart string) string {
	if idx := strings.Index(headerValuePart, ";"); idx != -1 {
		return headerValuePart[:idx]
	}
	return headerValuePart
}

func (d *ContentTypeProfile) GetContentTypeHeaderValues() string {
	processed := stripContentTypeParameters(d.rawContentTypeHeaderValue)
	processed = strings.TrimSpace(processed)
	return processed
}

func (d *ContentTypeProfile) GetAllHeaderInfo() []string {
	combinedMap := make(map[string]struct{})
	orderedResult := make([]string, 0)

	// Add Content-Type header if present
	if d.rawContentTypeHeaderValue != "" {
		combinedMap[d.rawContentTypeHeaderValue] = struct{}{}
		orderedResult = append(orderedResult, d.rawContentTypeHeaderValue)
	}

	// Add charset if present
	if d.detectedCharset != "" {
		charset := "charset=" + d.detectedCharset
		if _, exists := combinedMap[charset]; !exists {
			combinedMap[charset] = struct{}{}
			orderedResult = append(orderedResult, charset)
		}
	}

	// Add X-Content-Type-Options if present
	if d.xContentTypeOptionsHeaderValue != "" {
		if _, exists := combinedMap[d.xContentTypeOptionsHeaderValue]; !exists {
			combinedMap[d.xContentTypeOptionsHeaderValue] = struct{}{}
			orderedResult = append(orderedResult, d.xContentTypeOptionsHeaderValue)
		}
	}

	return orderedResult
}

func IsBinaryDef(defInstance *ContentTypeProfile) bool {
	if defInstance == nil {
		return false
	}
	return IsBinaryContentType(defInstance.inferredTypeCode) ||
		IsBinaryContentType(defInstance.statedTypeCode)
}

func isEffectiveType(defInstance *ContentTypeProfile, typeCode int16) bool {
	if defInstance == nil {
		return false
	}
	return defInstance.statedTypeCode == typeCode || defInstance.inferredTypeCode == typeCode
}

// GetIsText returns true if the effective type is PlainText.
func (d *ContentTypeProfile) GetIsText() bool {
	return isEffectiveType(d, DefTypePlainText)
}

// GetIsFlash returns true if the effective type is FlashObject.
func (d *ContentTypeProfile) GetIsFlash() bool {
	return isEffectiveType(d, DefTypeFlashObject)
}

func IsPlainTextDef(defInstance *ContentTypeProfile) bool {
	return isEffectiveType(defInstance, DefTypePlainText)
}

func IsHtmlDef(defInstance *ContentTypeProfile) bool {
	return isEffectiveType(defInstance, DefTypeHTML)
}

func IsScriptDef(defInstance *ContentTypeProfile) bool {
	return isEffectiveType(defInstance, DefTypeScript)
}

// func getContentTypeHeadersInternal(defInstance *Def) string {
// 	if defInstance == nil {
// 		return ""
// 	}
// 	return defInstance.contentTypeHeader
// }

// Helper to map mimetype_detector.ContentType to our int16 codes
func ContentTypeToDefCode(ct mimetype_detector.ContentType) int16 {
	switch ct {
	case mimetype_detector.ContentType_NONE:
		return DefTypeNone
	case mimetype_detector.ContentType_HTML:
		return DefTypeHTML
	case mimetype_detector.ContentType_PLAIN_TEXT:
		return DefTypePlainText
	case mimetype_detector.ContentType_CSS:
		return DefTypeCSS
	case mimetype_detector.ContentType_SCRIPT:
		return DefTypeScript
	case mimetype_detector.ContentType_JSON:
		return DefTypeJSON
	case mimetype_detector.ContentType_XML:
		return DefTypeXML
	case mimetype_detector.ContentType_RTF:
		return DefTypeRTF
	case mimetype_detector.ContentType_YAML:
		return DefTypeYAML
	case mimetype_detector.ContentType_SVG:
		return DefTypeSVGImage
	case mimetype_detector.ContentType_UNRECOGNIZED_CONTENT:
		return DefTypeUnrecognizedContent
	default:
		return DefTypeUnrecognizedContent
	}
}

// func newDefWithFhsMarker(
// 	statedType int16,
// 	inferredType int16,
// 	contentTypeHeadersSet []string,
// 	isNoSniff bool,
// 	isAttachment bool,
// 	xContentTypeOptionsHeadersSet []string,
// 	charsetsSet []string,
// ) *Def {
// 	return newDefInternal(statedType, inferredType, contentTypeHeadersSet, isNoSniff, isAttachment, xContentTypeOptionsHeadersSet, charsetsSet)
// }

// Helper to get CharsetRegex from mimetype_detector if not exposed
// This is a workaround as the original plan assumed direct access or helper.
// For now, this part of NewDef constructor is simplified.
// If mimetype_detector.CharsetRegex is needed, it should be exposed from that package.
// const cannotAccessCharsetRegexDirectly = true // Placeholder
