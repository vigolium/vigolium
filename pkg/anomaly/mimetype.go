package anomaly

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	httputil "github.com/projectdiscovery/utils/http"
)

type ContentType int

const (
	ContentTypeUnknown ContentType = iota
	ContentTypeHTML
	ContentTypeText
	ContentTypeScript
	ContentTypeYAML
	ContentTypeJSON
	ContentTypeXML
	ContentTypeCSS
	ContentTypeRichTextFormat
	ContentTypeFlash
	ContentTypeImage
	ContentTypeVideo
	ContentTypeAudio
	ContentTypeApplication
)

func (s ContentType) String() string {
	switch s {
	case ContentTypeUnknown:
		return "unknown"
	case ContentTypeHTML:
		return "html"
	case ContentTypeText:
		return "plain"
	case ContentTypeScript:
		return "javascript"
	case ContentTypeYAML:
		return "yaml"
	case ContentTypeJSON:
		return "json"
	case ContentTypeXML:
		return "xml"
	case ContentTypeCSS:
		return "css"
	case ContentTypeRichTextFormat:
		return "rtf"
	case ContentTypeFlash:
		return "flash"
	case ContentTypeImage:
		return "jpeg"
	case ContentTypeVideo:
		return "mp4"
	case ContentTypeAudio:
		return "mpeg"
	case ContentTypeApplication:
		return "app"
	}
	return "unknown"
}

type MimetypeDetector struct {
	statedMimeType   ContentType // from header
	inferredMimeType ContentType // from body
}

func NewMimetypeDetector(headers map[string][]string, body string) *MimetypeDetector {
	s := new(MimetypeDetector)
	s.analysis(headers, body)
	return s
}

func NewMimetypeDetector2(response interface{}) *MimetypeDetector {
	s := new(MimetypeDetector)
	switch response := response.(type) {
	case *httputil.ResponseChain:
		// headers := toLowerHeaders(response.Response().Header)
		s.analysis(response.Response().Header, response.Body().String())
	case *http.Response:
		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil {
			bodyBytes = []byte{}
		}
		response.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		s.analysis(response.Header, string(bodyBytes))
	}
	return s
}

func NewMimetypeDetector3(headers map[string]string, body string) *MimetypeDetector {
	headers2 := make(map[string][]string)
	for k, v := range headers {
		headers2[k] = []string{v}
	}
	s := new(MimetypeDetector)
	s.analysis(headers2, body)
	return s
}

func (s *MimetypeDetector) analysis(headers map[string][]string, body string) {
	if headers == nil {
		s.statedMimeType = ContentTypeUnknown
	} else {
		contentType := getContentTypeValue(headers)
		s.statedMimeType = s.getType(contentType)
	}

	mime := mimetype.Detect(s2b(body))
	s.inferredMimeType = s.getType(mime.String())
}

func (s *MimetypeDetector) getType(contentType string) ContentType {
	contentType = strings.ToLower(contentType)
	switch {
	case strings.Contains(contentType, "html") && !strings.Contains(contentType, "application/vnd"):
		return ContentTypeHTML
	case strings.Contains(contentType, "json"):
		return ContentTypeJSON
	case strings.Contains(contentType, "script"):
		return ContentTypeScript
	case strings.Contains(contentType, "text/plain"):
		return ContentTypeText
	case strings.Contains(contentType, "text/css"):
		return ContentTypeCSS
	case strings.Contains(contentType, "xml"):
		return ContentTypeXML
	case strings.Contains(contentType, "text/rtf"):
		return ContentTypeRichTextFormat
	case strings.Contains(contentType, "image"):
		return ContentTypeImage
	case strings.Contains(contentType, "sound") || strings.Contains(contentType, "audio"):
		return ContentTypeAudio
	case strings.Contains(contentType, "video") || strings.Contains(contentType, "application/ogg"):
		return ContentTypeVideo
	case strings.Contains(contentType, "application/x-shockwave-flash"):
		return ContentTypeFlash
	case strings.Contains(contentType, "yaml") || strings.Contains(contentType, "yml"):
		return ContentTypeYAML
	case strings.Contains(contentType, "application"):
		return ContentTypeApplication
	default:
		return ContentTypeUnknown
	}
}

// GetStatedMimeType This method is used to obtain the MIME type of the response, as stated in the HTTP headers.
func (s MimetypeDetector) GetStatedMimeType() ContentType {
	return s.statedMimeType
}

// GetInferredMimeType This method is used to obtain the MIME type of the response, as inferred from the contents
// of the HTTP message body.
func (s MimetypeDetector) GetInferredMimeType() ContentType {
	return s.inferredMimeType
}

func (s MimetypeDetector) Is(cts ...ContentType) bool {
	return s.hasContentType(s.inferredMimeType, cts...) || s.hasContentType(s.statedMimeType, cts...)
}

func (s MimetypeDetector) IsText() bool {
	found := s.hasContentType(s.inferredMimeType, ContentTypeText, ContentTypeHTML, ContentTypeScript, ContentTypeJSON, ContentTypeXML)
	if found {
		return found
	}
	found = s.hasContentType(s.statedMimeType, ContentTypeText, ContentTypeHTML, ContentTypeScript, ContentTypeJSON, ContentTypeXML)
	if found {
		return found
	}
	return false
}

func (s MimetypeDetector) IsTextIncludeCSS() bool {
	found := s.hasContentType(s.inferredMimeType, ContentTypeText, ContentTypeHTML, ContentTypeScript, ContentTypeJSON, ContentTypeXML, ContentTypeCSS)
	if found {
		return found
	}
	found = s.hasContentType(s.statedMimeType, ContentTypeText, ContentTypeHTML, ContentTypeScript, ContentTypeJSON, ContentTypeXML, ContentTypeCSS)
	if found {
		return found
	}
	return false
}

func (s MimetypeDetector) IsMedia() bool {
	found := s.hasContentType(s.inferredMimeType, ContentTypeAudio, ContentTypeImage, ContentTypeVideo, ContentTypeFlash)
	if found {
		return found
	}
	found = s.hasContentType(s.statedMimeType, ContentTypeAudio, ContentTypeImage, ContentTypeVideo, ContentTypeFlash)
	if found {
		return found
	}
	return false
}

func (s MimetypeDetector) IsImage() bool {
	if found := s.statedMimeType == ContentTypeImage; found {
		return true
	}
	if found := s.inferredMimeType == ContentTypeImage; found {
		return true
	}
	return false
}

func (s MimetypeDetector) IsJSON() bool {
	if found := s.statedMimeType == ContentTypeJSON; found {
		return true
	}
	if found := s.inferredMimeType == ContentTypeJSON; found {
		return true
	}
	return false
}

func (s MimetypeDetector) IsXML() bool {
	if found := s.statedMimeType == ContentTypeXML; found {
		return true
	}
	if found := s.inferredMimeType == ContentTypeXML; found {
		return true
	}
	return false
}

func (s MimetypeDetector) IsHTML() bool {
	if found := s.statedMimeType == ContentTypeHTML; found {
		return true
	}
	if found := s.inferredMimeType == ContentTypeHTML; found {
		return true
	}
	return false
}

func (s MimetypeDetector) IsApplication() bool {
	if found := s.inferredMimeType == ContentTypeApplication; found {
		return true
	}
	if found := s.statedMimeType == ContentTypeApplication; found {
		return true
	}
	return false
}

func (s MimetypeDetector) IsUnknown() bool {
	return s.inferredMimeType == ContentTypeUnknown && s.statedMimeType == ContentTypeUnknown
}

func (s MimetypeDetector) IsJavascript() bool {
	if found := s.inferredMimeType == ContentTypeScript; found {
		return true
	}
	if found := s.statedMimeType == ContentTypeScript; found {
		return true
	}
	return false
}

func (s MimetypeDetector) IsPlainText() bool {
	if found := s.inferredMimeType == ContentTypeText; found {
		return true
	}
	if found := s.statedMimeType == ContentTypeText; found {
		return true
	}
	return false
}

func (s MimetypeDetector) String() string {
	return fmt.Sprintf("%s|%s", s.inferredMimeType, s.statedMimeType)
}

func (s MimetypeDetector) hasContentType(toCompare ContentType, cts ...ContentType) bool {
	for _, ct := range cts {
		if ct == toCompare {
			return true
		}
	}
	return false
}
