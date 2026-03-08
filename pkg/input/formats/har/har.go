package har

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"go.uber.org/zap"
)

// Format implements formats.Format for HAR (HTTP Archive) files.
type Format struct {
	formatOpts formats.InputFormatOptions
}

// New creates a new HAR Format parser.
func New() *Format {
	return &Format{}
}

var _ formats.Format = &Format{}

// Name returns the format name.
func (f *Format) Name() string {
	return "har"
}

// SetOptions sets generic format options.
func (f *Format) SetOptions(options formats.InputFormatOptions) {
	f.formatOpts = options
}

// Parse reads a HAR file and calls callback for each parsed entry.
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("failed to read HAR file: %w", err)
	}
	return f.ParseFromData(data, callback)
}

// ParseFromData parses HAR JSON data and calls callback for each entry.
func (f *Format) ParseFromData(data []byte, callback formats.ParseReqRespCallback) error {
	var harFile harArchive
	if err := json.Unmarshal(data, &harFile); err != nil {
		return fmt.Errorf("failed to parse HAR JSON: %w", err)
	}

	for _, entry := range harFile.Log.Entries {
		rr := f.processEntry(&entry)
		if rr == nil {
			continue
		}
		if !callback(rr) {
			return nil
		}
	}

	return nil
}

// Count returns the number of entries in the HAR file.
func (f *Format) Count(input string) (int64, error) {
	data, err := os.ReadFile(input)
	if err != nil {
		return 0, err
	}

	var harFile harArchive
	if err := json.Unmarshal(data, &harFile); err != nil {
		return 0, err
	}

	return int64(len(harFile.Log.Entries)), nil
}

// processEntry converts a HAR entry into an HttpRequestResponse.
func (f *Format) processEntry(entry *harEntry) *httpmsg.HttpRequestResponse {
	rawReq := buildRawRequest(&entry.Request)
	if rawReq == "" {
		return nil
	}

	reqURL := entry.Request.URL
	if reqURL == "" {
		return nil
	}

	var rr *httpmsg.HttpRequestResponse
	var err error

	rr, err = httpmsg.ParseRawRequestWithURL(rawReq, reqURL)
	if err != nil {
		zap.L().Debug("har: failed to parse request",
			zap.String("url", reqURL),
			zap.Error(err))
		return nil
	}

	// Attach response if present
	if entry.Response.Status > 0 {
		rawResp := buildRawResponse(&entry.Response)
		if rawResp != "" {
			resp := httpmsg.NewHttpResponse([]byte(rawResp))
			if resp != nil {
				rr = rr.WithResponse(resp)
			}
		}
	}

	return rr
}

// buildRawRequest constructs a raw HTTP request string from a HAR request object.
func buildRawRequest(req *harRequest) string {
	if req.Method == "" || req.URL == "" {
		return ""
	}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return ""
	}

	path := parsedURL.RequestURI()
	if path == "" {
		path = "/"
	}

	httpVersion := req.HTTPVersion
	if httpVersion == "" {
		httpVersion = "HTTP/1.1"
	}

	var sb strings.Builder

	// Request line
	sb.WriteString(fmt.Sprintf("%s %s %s\r\n", req.Method, path, httpVersion))

	// Headers
	hasHost := false
	for _, h := range req.Headers {
		name := h.Name
		// Skip pseudo-headers (HTTP/2)
		if strings.HasPrefix(name, ":") {
			continue
		}
		if strings.EqualFold(name, "Host") {
			hasHost = true
		}
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", name, h.Value))
	}

	// Add Host header if missing
	if !hasHost && parsedURL.Host != "" {
		sb.WriteString(fmt.Sprintf("Host: %s\r\n", parsedURL.Host))
	}

	// Body
	if req.PostData != nil && req.PostData.Text != "" {
		sb.WriteString("\r\n")
		sb.WriteString(req.PostData.Text)
	} else {
		sb.WriteString("\r\n")
	}

	return sb.String()
}

// buildRawResponse constructs a raw HTTP response string from a HAR response object.
func buildRawResponse(resp *harResponse) string {
	httpVersion := resp.HTTPVersion
	if httpVersion == "" {
		httpVersion = "HTTP/1.1"
	}

	statusText := resp.StatusText
	if statusText == "" {
		statusText = "OK"
	}

	var sb strings.Builder

	// Status line
	sb.WriteString(fmt.Sprintf("%s %d %s\r\n", httpVersion, resp.Status, statusText))

	// Headers
	for _, h := range resp.Headers {
		if strings.HasPrefix(h.Name, ":") {
			continue
		}
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", h.Name, h.Value))
	}

	// Body
	sb.WriteString("\r\n")
	if resp.Content.Text != "" {
		sb.WriteString(resp.Content.Text)
	}

	return sb.String()
}

// HAR format types

type harArchive struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Entries []harEntry `json:"entries"`
}

type harEntry struct {
	Request  harRequest  `json:"request"`
	Response harResponse `json:"response"`
}

type harRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	QueryString []harQuery  `json:"queryString"`
	PostData    *harPost    `json:"postData"`
}

type harResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	Content     harContent  `json:"content"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harQuery struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}
