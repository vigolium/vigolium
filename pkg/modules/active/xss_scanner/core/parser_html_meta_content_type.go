package core

import (
	"net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/mimetype_detector"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
)

// RefineContentTypeWithHTMLMeta analyzes HTML elements to potentially refine content type information.
// Currently, it checks for <meta http-equiv="Content-Type">.
// Due to Def being mostly immutable after creation and newDefInternal being private,
// this function currently returns the originalDef.
// A more complete implementation would require Def to be mutable or for this function
// to have access to all original http.Response parts to construct a new Def.
func RefineContentTypeWithHTMLMeta(
	currentProfile *ContentTypeProfile,
	elements []*htmlparser.HTMLElement,
	responseHeaders http.Header,
	responseBody []byte,
	shouldStop func() bool,
) *ContentTypeProfile {
	if shouldStop != nil && shouldStop() {
		if currentProfile == nil {
			// Return a very basic default Def if everything is nil/stopped early
			return NewContentTypeProfile(responseHeaders, responseBody)
		}
		return currentProfile
	}

	var metaMimeType string
	var metaCharset string // Charset from meta can be stored if Def is extended

	for _, htmlElement := range elements {
		if shouldStop != nil && shouldStop() {
			break
		}
		if htmlElement.Type == htmlparser.OpenTag && htmlElement.TagInfo != nil &&
			strings.EqualFold(htmlElement.TagInfo.Name, "meta") {
			httpEquivValue := ""
			contentValue := ""
			for _, attr := range htmlElement.TagInfo.Attributes {
				if strings.EqualFold(attr.Name, "http-equiv") {
					httpEquivValue = strings.ToLower(attr.Value)
				} else if strings.EqualFold(attr.Name, "content") {
					contentValue = attr.Value
				}
			}

			if httpEquivValue == "content-type" && contentValue != "" {
				contentParts := strings.Split(contentValue, ";")
				if len(contentParts) > 0 {
					metaMimeType = strings.ToLower(strings.TrimSpace(contentParts[0]))
				}
				for _, contentPart := range contentParts {
					trimmedContentPart := strings.ToLower(strings.TrimSpace(contentPart))
					if strings.HasPrefix(trimmedContentPart, "charset=") {
						metaCharset = strings.TrimPrefix(trimmedContentPart, "charset=")
						break
					}
				}
				// fmt.Printf("ea5: Found meta content-type: %s, charset: %s\n", foundMetaMime, foundMetaCharset)
				// For now, just finding the mime is enough to demonstrate.
				// If foundMetaMime is valid and different from originalDef.StatedType, a new Def object
				// would ideally be created here, or originalDef updated if it were mutable.
				// Since newDefInternal is private and needs full context, we cannot easily create a new full Def here.
				// And originalDef is largely immutable for stated/inferred types after creation.
				// So, this placeholder will not alter originalDef but shows how info could be found.
				break // Found relevant meta tag, no need to check further elements
			}
		}
	}

	if metaMimeType != "" {
		_, statedMimeFromMeta := mimetype_detector.GetStatedInferredContentType(
			metaMimeType,
		)
		newStatedTypeCodeFromMeta := ContentTypeToDefCode(statedMimeFromMeta)

		// contentTypeHeaderStringFromMeta is built for completeness but not used currently
		_ = metaCharset // Charset is captured but not used in header string construction

		shouldUpdateProfileFromMeta := false
		if currentProfile == nil && newStatedTypeCodeFromMeta != DefTypeNone {
			shouldUpdateProfileFromMeta = true
		} else if currentProfile != nil && newStatedTypeCodeFromMeta != currentProfile.GetStatedTypeCode() && newStatedTypeCodeFromMeta != DefTypeNone {
			shouldUpdateProfileFromMeta = true
		}

		if shouldUpdateProfileFromMeta {
			return NewContentTypeProfile(responseHeaders, responseBody)
		}
	}

	if currentProfile == nil {
		// If originalDef was nil, and we found a meta tag, we could try to create a new Def.
		// But NewDef requires http.Header and body, which are not available here.
		// So, return a basic default.
		return NewContentTypeProfile(responseHeaders, responseBody)
	}

	return currentProfile
}
