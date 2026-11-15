package har

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/vigolium/vigolium/pkg/input/formats/internal/jsonstream"
	"github.com/vigolium/vigolium/pkg/input/formats/internal/multipartform"
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

// Parse streams a HAR file and calls callback for each parsed entry. Only one
// entry is decoded at a time, so memory stays bounded however large the
// archive is (see stream.go).
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	fh, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("failed to read HAR file: %w", err)
	}
	defer func() { _ = fh.Close() }()
	return f.ParseReader(fh, callback)
}

// ParseFromData parses HAR JSON data and calls callback for each entry.
func (f *Format) ParseFromData(data []byte, callback formats.ParseReqRespCallback) error {
	return f.ParseReader(bytes.NewReader(data), callback)
}

// ParseReader streams HAR JSON from r and calls callback for each entry.
//
// Entries are emitted as they are decoded, so a document that turns out to be
// malformed further on returns an error after the entries before the damage
// were delivered. A callback returning false stops the parse; the rest of the
// input is not read.
func (f *Format) ParseReader(r io.Reader, callback formats.ParseReqRespCallback) error {
	err := walkEntries(r, func(dec *json.Decoder, i int) (bool, error) {
		var entry harEntry
		if err := dec.Decode(&entry); err != nil {
			return false, fmt.Errorf("log.entries[%d]: %w", i, err)
		}
		rr := f.processEntry(&entry)
		if rr == nil {
			return true, nil
		}
		return callback(rr), nil
	})
	if err != nil {
		return fmt.Errorf("failed to parse HAR JSON: %w", err)
	}
	return nil
}

// Count returns the number of entries in the HAR file. It walks the document
// with the same token stream as Parse but skips each entry without decoding
// it, so it allocates next to nothing beyond the decoder's buffer.
func (f *Format) Count(input string) (int64, error) {
	fh, err := os.Open(input)
	if err != nil {
		return 0, err
	}
	defer func() { _ = fh.Close() }()

	var n int64
	err = walkEntries(fh, func(dec *json.Decoder, _ int) (bool, error) {
		n++
		return true, jsonstream.SkipValue(dec)
	})
	if err != nil {
		return 0, err
	}
	return n, nil
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
			// The capture's own timing is a real measurement of this exchange,
			// so it is kept; an untimed entry stays "unknown".
			var resp *httpmsg.HttpResponse
			if entry.Time != nil && *entry.Time > 0 {
				resp = httpmsg.NewHttpResponseWithDuration([]byte(rawResp), time.Duration(*entry.Time*float64(time.Millisecond)))
			} else {
				resp = httpmsg.NewHttpResponse([]byte(rawResp))
			}
			if resp != nil {
				rr = rr.WithResponse(resp)
			}
		}
	}

	return rr
}

// buildRawRequest constructs a raw HTTP request string from a HAR request object.
//
// The result is always an HTTP/1.1 message, whatever protocol the browser
// recorded: the scanner speaks HTTP/1.1 on the wire, so an `h2`/`HTTP/2.0`/`h3`
// request line would only produce a request the transport rewrites or rejects.
// HTTP/2 pseudo-headers are dropped (`:authority` becomes Host), and
// Content-Length is set to the body actually emitted, because a body rebuilt
// from `postData.params` rarely has the byte length the browser declared.
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

	body, contentType := buildRequestBody(req)

	// Host comes from a real Host header, else HTTP/2's :authority, else the URL.
	host := ""
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "Host") {
			host = h.Value
			break
		}
	}
	if host == "" {
		for _, h := range req.Headers {
			if strings.EqualFold(h.Name, ":authority") {
				host = h.Value
				break
			}
		}
	}
	if host == "" {
		host = parsedURL.Host
	}

	var sb strings.Builder

	// Request line
	fmt.Fprintf(&sb, "%s %s %s\r\n", req.Method, path, normalizeHTTPVersion(req.HTTPVersion))
	if host != "" {
		fmt.Fprintf(&sb, "Host: %s\r\n", host)
	}

	// Headers
	hasContentType, hasContentLength := false, false
	for _, h := range req.Headers {
		name := h.Name
		switch {
		case strings.HasPrefix(name, ":"), strings.EqualFold(name, "Host"):
			// Pseudo-headers (HTTP/2) and Host were folded into the Host line.
			continue
		case strings.EqualFold(name, "Transfer-Encoding"):
			// The body is emitted unchunked with an explicit Content-Length.
			continue
		case strings.EqualFold(name, "Content-Type") && contentType != "":
			hasContentType = true
			fmt.Fprintf(&sb, "%s: %s\r\n", name, contentType)
			continue
		case strings.EqualFold(name, "Content-Length"):
			if hasContentLength {
				continue
			}
			hasContentLength = true
			if body != "" || h.Value != "0" {
				fmt.Fprintf(&sb, "%s: %d\r\n", name, len(body))
				continue
			}
		}
		fmt.Fprintf(&sb, "%s: %s\r\n", name, h.Value)
	}
	if contentType != "" && !hasContentType {
		fmt.Fprintf(&sb, "Content-Type: %s\r\n", contentType)
	}
	if body != "" && !hasContentLength {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}

	sb.WriteString("\r\n")
	sb.WriteString(body)

	return sb.String()
}

// buildRequestBody returns the request body to emit and, when the body was
// synthesized from `postData.params`, the Content-Type that describes it (empty
// when the recorded Content-Type header should be kept as is).
//
// HAR stores a form either as `text` or as `params` (or both). `text` wins when
// present because it is the exact bytes the browser sent; `params` alone is
// rebuilt as application/x-www-form-urlencoded or, for a multipart mimeType,
// multipart/form-data.
func buildRequestBody(req *harRequest) (body, contentType string) {
	pd := req.PostData
	if pd == nil {
		return "", ""
	}
	if pd.Text != "" {
		if strings.EqualFold(pd.Encoding, "base64") {
			if decoded, ok := decodeBase64(pd.Text); ok {
				return decoded, ""
			}
		}
		return pd.Text, ""
	}
	if len(pd.Params) == 0 {
		return "", ""
	}

	mimeType := pd.MimeType
	if mimeType == "" {
		mimeType = headerValue(req.Headers, "Content-Type")
	}
	mediaType, params, _ := mime.ParseMediaType(mimeType)
	if strings.EqualFold(mediaType, "multipart/form-data") {
		boundary := params["boundary"]
		if boundary == "" {
			if _, hp, err := mime.ParseMediaType(headerValue(req.Headers, "Content-Type")); err == nil {
				boundary = hp["boundary"]
			}
		}
		b, ct, err := buildMultipart(pd.Params, boundary)
		if err == nil {
			return b, ct
		}
		zap.L().Debug("har: failed to build multipart body", zap.Error(err))
	}

	// Encoded by hand rather than url.Values.Encode, which sorts by key: the
	// recorded field order is part of the request.
	pairs := make([]string, 0, len(pd.Params))
	for _, p := range pd.Params {
		pairs = append(pairs, url.QueryEscape(p.Name)+"="+url.QueryEscape(p.Value))
	}
	return strings.Join(pairs, "&"), "application/x-www-form-urlencoded"
}

// defaultMultipartBoundary is used when neither postData.mimeType nor the
// Content-Type header names one. It is fixed rather than random so the same
// HAR always yields the same request (and the same dedup identity).
const defaultMultipartBoundary = "----VigoliumHARFormBoundary7MA4YWxkTrZu0gW"

// buildMultipart renders HAR form params as a multipart/form-data body. File
// params carry their recorded value (usually empty: browsers do not export
// uploaded file contents) under their fileName and contentType.
func buildMultipart(params []harParam, boundary string) (string, string, error) {
	if boundary == "" {
		boundary = defaultMultipartBoundary
	}
	parts := make([]multipartform.Part, len(params))
	for i, p := range params {
		parts[i] = multipartform.Part{Name: p.Name, FileName: p.FileName, Value: p.Value}
		if p.FileName != "" {
			// A recorded contentType only applies to file params.
			parts[i].ContentType = p.ContentType
		}
	}
	return multipartform.Build(parts, boundary)
}

// buildRawResponse constructs a raw HTTP response string from a HAR response object.
//
// HAR's content.text is the *decoded* body (the spec says so, and Chrome and
// Firefox both comply), optionally base64-wrapped for binary content. The
// recorded Content-Encoding/Transfer-Encoding no longer describe those bytes,
// so they are dropped and Content-Length is set to the body actually emitted.
// When the archive omitted the body, the recorded headers are kept unchanged.
func buildRawResponse(resp *harResponse) string {
	statusText := resp.StatusText
	if statusText == "" {
		statusText = http.StatusText(resp.Status)
	}

	body := resp.Content.Text
	if body != "" && strings.EqualFold(resp.Content.Encoding, "base64") {
		if decoded, ok := decodeBase64(body); ok {
			body = decoded
		}
	}

	var sb strings.Builder

	// Status line
	fmt.Fprintf(&sb, "%s %d", normalizeHTTPVersion(resp.HTTPVersion), resp.Status)
	if statusText != "" {
		sb.WriteString(" ")
		sb.WriteString(statusText)
	}
	sb.WriteString("\r\n")

	// Headers
	hasContentLength := false
	for _, h := range resp.Headers {
		if strings.HasPrefix(h.Name, ":") {
			continue
		}
		if body != "" {
			switch {
			case strings.EqualFold(h.Name, "Content-Encoding"),
				strings.EqualFold(h.Name, "Transfer-Encoding"):
				continue
			case strings.EqualFold(h.Name, "Content-Length"):
				if !hasContentLength {
					hasContentLength = true
					fmt.Fprintf(&sb, "%s: %d\r\n", h.Name, len(body))
				}
				continue
			}
		}
		fmt.Fprintf(&sb, "%s: %s\r\n", h.Name, h.Value)
	}
	if body != "" && !hasContentLength {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}

	// Body
	sb.WriteString("\r\n")
	sb.WriteString(body)

	return sb.String()
}

// normalizeHTTPVersion maps whatever protocol label a browser recorded onto the
// HTTP/1.x version the scanner sends. HTTP/1.0 is kept; everything else —
// `h2`, `HTTP/2`, `HTTP/2.0`, `h3`, `http/1.1`, `unknown`, empty — becomes
// HTTP/1.1. No record field carries the original protocol, so it is not kept.
func normalizeHTTPVersion(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), "HTTP/1.0") {
		return "HTTP/1.0"
	}
	return "HTTP/1.1"
}

// decodeBase64 decodes a HAR base64 body, accepting both padded and unpadded
// standard encodings (exporters differ).
func decodeBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b), true
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return string(b), true
	}
	return "", false
}

func headerValue(headers []harHeader, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// HAR format types

type harEntry struct {
	Request  harRequest  `json:"request"`
	Response harResponse `json:"response"`
	// Time is the entry's total elapsed time in milliseconds; -1 (or absent)
	// when the browser did not time it.
	Time *float64 `json:"time"`
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
	MimeType string     `json:"mimeType"`
	Text     string     `json:"text"`
	Params   []harParam `json:"params"`
	// Encoding is not in the HAR 1.2 spec for postData, but some exporters
	// mirror content.encoding here for binary request bodies.
	Encoding string `json:"encoding"`
}

type harParam struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	FileName    string `json:"fileName"`
	ContentType string `json:"contentType"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding"`
}
