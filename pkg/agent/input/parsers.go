package input

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"go.uber.org/zap"
)

// parseCurlCommand parses a curl command string into an HttpRequestResponse.
func parseCurlCommand(cmd string) (*httpmsg.HttpRequestResponse, error) {
	return curl.ParseSingleCommand(cmd)
}

// burpItem represents a single item in Burp Suite XML export.
type burpItem struct {
	XMLName  xml.Name `xml:"item"`
	URL      string   `xml:"url"`
	Host     string   `xml:"host"`
	Port     string   `xml:"port"`
	Protocol string   `xml:"protocol"`
	Method   string   `xml:"method"`
	Path     string   `xml:"path"`
	Request  burpData `xml:"request"`
	Response burpData `xml:"response"`
	Status   string   `xml:"status"`
}

type burpData struct {
	Base64  string `xml:"base64,attr"`
	Content string `xml:",chardata"`
}

// parseBurpXML parses Burp Suite XML format into HttpRequestResponse objects.
func parseBurpXML(input string) ([]*httpmsg.HttpRequestResponse, error) {
	decoder := xml.NewDecoder(strings.NewReader(input))
	decoder.Strict = false

	var results []*httpmsg.HttpRequestResponse

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		se, ok := token.(xml.StartElement)
		if !ok || se.Name.Local != "item" {
			continue
		}

		var item burpItem
		if err := decoder.DecodeElement(&item, &se); err != nil {
			zap.L().Warn("Skipping malformed Burp XML item", zap.Error(err))
			continue
		}

		reqData := item.Request.Content
		if item.Request.Base64 == "true" {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(reqData))
			if err != nil {
				zap.L().Warn("Skipping Burp XML item: failed to decode base64 request", zap.Error(err))
				continue
			}
			reqData = string(decoded)
		}

		if reqData == "" {
			continue
		}

		targetURL := item.URL
		if targetURL == "" && item.Host != "" {
			targetURL = fmt.Sprintf("%s://%s%s", item.Protocol, item.Host, item.Path)
		}

		rr, err := httpmsg.ParseRawRequestWithURL(reqData, targetURL)
		if err != nil {
			zap.L().Warn("Skipping Burp XML item: failed to parse raw request",
				zap.String("url", targetURL), zap.Error(err))
			continue
		}

		// Attach response if present
		if item.Response.Content != "" {
			respData := item.Response.Content
			if item.Response.Base64 == "true" {
				decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(respData))
				if err == nil {
					respData = string(decoded)
				}
			}
			resp := httpmsg.NewHttpResponse([]byte(respData))
			rr = rr.WithResponse(resp)
		}

		results = append(results, rr)
	}

	return results, nil
}
