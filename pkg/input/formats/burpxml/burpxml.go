package burpxml

import (
	"bufio"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"go.uber.org/zap"
)

// Format implements formats.Format for Burp Suite XML session/state files.
// These contain multiple <item> elements with request/response data,
// either as raw text or base64-encoded.
type Format struct {
	formatOpts formats.InputFormatOptions
}

// New creates a new burpxml Format parser.
func New() *Format {
	return &Format{}
}

var _ formats.Format = &Format{}

// Name returns the format name.
func (f *Format) Name() string {
	return "burpxml"
}

// SetOptions sets generic format options.
func (f *Format) SetOptions(options formats.InputFormatOptions) {
	f.formatOpts = options
}

// burpItem represents a single <item> element in Burp XML.
type burpItem struct {
	URL      string      `xml:"url"`
	Host     burpHost    `xml:"host"`
	Port     int         `xml:"port"`
	Protocol string      `xml:"protocol"`
	Method   string      `xml:"method"`
	Path     string      `xml:"path"`
	Request  burpContent `xml:"request"`
	Response burpContent `xml:"response"`
	Status   int         `xml:"status"`
}

// burpHost represents a <host> element with an optional ip attribute.
type burpHost struct {
	Value string `xml:",chardata"`
	IP    string `xml:"ip,attr"`
}

// burpContent represents request/response content with an optional base64 attribute.
type burpContent struct {
	Value  string `xml:",chardata"`
	Base64 string `xml:"base64,attr"`
}

// Parse reads a Burp XML file and calls callback for each parsed request item.
// Uses streaming XML parsing to handle large files efficiently.
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	file, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("failed to open burp xml file: %w", err)
	}
	defer func() { _ = file.Close() }()

	reader := patchXMLVersion(file)

	decoder := xml.NewDecoder(reader)
	// Burp XML files may contain raw bytes that are not valid UTF-8
	decoder.Strict = false
	decoder.CharsetReader = func(charset string, r io.Reader) (io.Reader, error) {
		return r, nil
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break // EOF or error
		}

		startElem, ok := token.(xml.StartElement)
		if !ok || startElem.Name.Local != "item" {
			continue
		}

		var item burpItem
		if err := decoder.DecodeElement(&item, &startElem); err != nil {
			zap.L().Debug("burpxml: failed to decode item", zap.Error(err))
			continue
		}

		rr := f.processItem(&item)
		if rr == nil {
			continue
		}

		if !callback(rr) {
			return nil
		}
	}

	return nil
}

// Count returns the number of <item> elements in the Burp XML file.
func (f *Format) Count(input string) (int64, error) {
	file, err := os.Open(input)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	reader := patchXMLVersion(file)

	var count int64
	decoder := xml.NewDecoder(reader)
	decoder.Strict = false
	decoder.CharsetReader = func(charset string, r io.Reader) (io.Reader, error) {
		return r, nil
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if startElem, ok := token.(xml.StartElement); ok && startElem.Name.Local == "item" {
			count++
			if err := decoder.Skip(); err != nil {
				break
			}
		}
	}

	return count, nil
}

// patchXMLVersion reads the first line of the file and replaces XML 1.1 with 1.0
// since Go's encoding/xml only supports XML 1.0. Burp Suite exports may use XML 1.1.
func patchXMLVersion(file *os.File) io.Reader {
	br := bufio.NewReader(file)
	firstLine, err := br.ReadString('\n')
	if err != nil {
		// File might be one line; reset and return as-is
		_, _ = file.Seek(0, io.SeekStart)
		return file
	}

	patched := strings.Replace(firstLine, `version="1.1"`, `version="1.0"`, 1)
	return io.MultiReader(strings.NewReader(patched), br)
}

// processItem converts a burpItem into an HttpRequestResponse.
func (f *Format) processItem(item *burpItem) *httpmsg.HttpRequestResponse {
	// Decode request content
	requestRaw, err := decodeContent(&item.Request)
	if err != nil {
		zap.L().Debug("burpxml: failed to decode request content",
			zap.String("url", item.URL),
			zap.Error(err))
		return nil
	}

	if strings.TrimSpace(requestRaw) == "" {
		return nil
	}

	// Build URL from item metadata
	itemURL := buildURL(item)

	var rr *httpmsg.HttpRequestResponse
	if itemURL != "" {
		rr, err = httpmsg.ParseRawRequestWithURL(requestRaw, itemURL)
	} else {
		rr, err = httpmsg.ParseRawRequest(requestRaw)
	}
	if err != nil {
		zap.L().Debug("burpxml: failed to parse request",
			zap.String("url", item.URL),
			zap.Error(err))
		return nil
	}

	return rr
}

// decodeContent decodes a burpContent value, handling base64 encoding if specified.
func decodeContent(content *burpContent) (string, error) {
	if content.Base64 == "true" {
		decoded, err := base64.StdEncoding.DecodeString(content.Value)
		if err != nil {
			return "", fmt.Errorf("base64 decode failed: %w", err)
		}
		return string(decoded), nil
	}
	return content.Value, nil
}

// buildURL constructs a full URL from item metadata fields.
func buildURL(item *burpItem) string {
	protocol := item.Protocol
	if protocol == "" {
		protocol = "https"
	}

	host := item.Host.Value
	if host == "" {
		return ""
	}

	port := item.Port
	path := item.Path

	// Build URL, only include port if non-standard
	var urlBuilder strings.Builder
	urlBuilder.WriteString(protocol)
	urlBuilder.WriteString("://")
	urlBuilder.WriteString(host)

	if port > 0 && !isStandardPort(protocol, port) {
		urlBuilder.WriteString(":")
		urlBuilder.WriteString(strconv.Itoa(port))
	}

	if path != "" {
		if !strings.HasPrefix(path, "/") {
			urlBuilder.WriteString("/")
		}
		urlBuilder.WriteString(path)
	} else {
		urlBuilder.WriteString("/")
	}

	return urlBuilder.String()
}

// isStandardPort returns true if the port is standard for the given protocol.
func isStandardPort(protocol string, port int) bool {
	return (protocol == "https" && port == 443) || (protocol == "http" && port == 80)
}
