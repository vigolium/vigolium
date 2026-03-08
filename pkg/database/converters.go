package database

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/anomaly/htmlutils"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// FromHttpRequestResponse populates an HTTPRecord from httpmsg.HttpRequestResponse
func (r *HTTPRecord) FromHttpRequestResponse(ctx *httpmsg.HttpRequestResponse) error {
	if ctx == nil || ctx.Request() == nil {
		return fmt.Errorf("invalid HttpRequestResponse")
	}

	req := ctx.Request()
	u, err := ctx.URL()
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Generate UUID
	r.UUID = uuid.New().String()

	// Host info
	r.Scheme = u.Scheme
	r.Hostname = u.Hostname()
	port := 0
	if u.Port() != "" {
		_, _ = fmt.Sscanf(u.Port(), "%d", &port)
	} else if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	r.Port = port

	// Request fields
	r.Method = req.Method()
	r.Path = req.Path()
	r.HTTPVersion = "HTTP/1.1"
	r.URL = u.String()

	// Request headers
	r.RequestHeaders = make(map[string][]string)
	for _, h := range req.Headers() {
		r.RequestHeaders[h.Name] = append(r.RequestHeaders[h.Name], h.Value)
	}

	// Request body metadata
	r.RequestContentType = req.Header("Content-Type")
	r.RequestContentLength = int64(len(req.Body()))

	// Request authorization (prefer Authorization header, fall back to Cookie)
	if auth := req.Header("Authorization"); auth != "" {
		r.RequestAuthorization = auth
	} else if cookie := req.Header("Cookie"); cookie != "" {
		r.RequestAuthorization = cookie
	}

	// Raw request data
	r.RawRequest = req.Raw()
	r.RequestBody = req.Body()

	// Request hash
	hash := sha256.Sum256(r.RawRequest)
	r.RequestHash = hex.EncodeToString(hash[:])

	// Response (if available)
	if ctx.HasResponse() {
		resp := ctx.Response()
		r.HasResponse = true
		r.StatusCode = resp.StatusCode()
		r.ResponseHTTPVersion = "HTTP/1.1"

		// Response headers
		r.ResponseHeaders = make(map[string][]string)
		for _, h := range resp.Headers() {
			r.ResponseHeaders[h.Name] = append(r.ResponseHeaders[h.Name], h.Value)
		}

		r.ResponseContentType = resp.Header("Content-Type")
		r.ResponseContentLength = int64(len(resp.Body()))
		r.RawResponse = resp.Raw()
		r.ResponseBody = resp.Body()

		// Extract HTML title for quick reference
		if strings.Contains(strings.ToLower(r.ResponseContentType), "html") {
			r.ResponseTitle = extractHTMLTitle(r.ResponseBody)
		}

		// Count words in response body and headers
		r.ResponseWords = countResponseWords(r.ResponseBody, r.ResponseHeaders)

		respHash := sha256.Sum256(r.RawResponse)
		r.ResponseHash = hex.EncodeToString(respHash[:])

		r.ReceivedAt = time.Now()
	}

	// Parameters
	params, err := req.Parameters()
	if err == nil && len(params) > 0 {
		r.Parameters = make([]EmbeddedParam, 0, len(params))
		for _, p := range params {
			r.Parameters = append(r.Parameters, EmbeddedParam{
				Name:       p.Name(),
				Value:      p.Value(),
				Type:       ParameterTypeFromParamType(p.Type()),
				NameStart:  p.NameStart(),
				NameEnd:    p.NameEnd(),
				ValueStart: p.ValueStart(),
				ValueEnd:   p.ValueEnd(),
			})
		}
	}

	// Timestamps
	r.SentAt = time.Now()

	return nil
}

// FromResultEvent converts output.ResultEvent to Finding
func (f *Finding) FromResultEvent(event *output.ResultEvent) error {
	if event == nil {
		return fmt.Errorf("invalid ResultEvent")
	}

	f.ModuleID = event.ModuleID
	f.ModuleName = event.Info.Name
	f.Description = event.Info.Description
	f.Severity = event.Info.Severity.String()
	f.Confidence = event.Info.Confidence.String()
	f.Tags = event.Info.Tags

	if event.Matched != "" {
		f.MatchedAt = []string{event.Matched}
	}
	f.ExtractedResults = event.ExtractedResults

	f.Request = event.Request
	f.Response = event.Response
	f.AdditionalEvidence = event.AdditionalEvidence
	f.ModuleType = event.ModuleType
	f.FindingSource = event.FindingSource
	f.ModuleShort = event.ModuleShort

	f.FindingHash = event.ID()
	f.FoundAt = time.Now()

	return nil
}

// extractHTMLTitle parses the <title> element from an HTML body.
// Returns empty string on parse failure or missing title. Caps at 512 chars.
func extractHTMLTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	doc, err := htmlutils.FastParse(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	tags := htmlutils.GetElementsByTagName(doc, "title")
	if len(tags) == 0 {
		return ""
	}
	title := strings.TrimSpace(htmlutils.TextContent(tags[0]))
	if len(title) > 512 {
		title = title[:512]
	}
	return title
}

// countResponseWords counts whitespace-delimited words in the response body and headers.
// Uses byte-level scanning to avoid allocating a string copy or []string slice.
func countResponseWords(body []byte, headers map[string][]string) int64 {
	count := int64(countWordsBytes(body))
	for k, vals := range headers {
		count += int64(countWordsString(k))
		for _, v := range vals {
			count += int64(countWordsString(v))
		}
	}
	return count
}

// countWordsBytes counts whitespace-delimited words in a byte slice without allocations.
func countWordsBytes(b []byte) int {
	n := 0
	inWord := false
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}

// countWordsString counts whitespace-delimited words in a string without allocations.
func countWordsString(s string) int {
	n := 0
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}

// ParameterTypeFromParamType converts ParamType to database parameter type string
func ParameterTypeFromParamType(ptype httpmsg.ParamType) string {
	switch ptype {
	case httpmsg.ParamURL:
		return "url"
	case httpmsg.ParamBody, httpmsg.ParamBodyMultipart:
		return "body"
	case httpmsg.ParamJSON:
		return "json"
	case httpmsg.ParamXML, httpmsg.ParamXMLAttr:
		return "xml"
	case httpmsg.ParamCookie:
		return "cookie"
	case httpmsg.ParamPathFolder, httpmsg.ParamPathFilename:
		return "path"
	case httpmsg.ParamMultipartAttr:
		return "multipart"
	default:
		return "unknown"
	}
}
