package burpxml

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
)

// testXML is a small Burp Suite session export with two items: the first uses
// base64-encoded request/response content, the second uses raw (un-encoded)
// content. Note the XML version 1.1 declaration which the parser patches to 1.0.
const testXML = `<?xml version="1.1" encoding="UTF-8"?>
<items>
  <item>
    <url>https://example.com/api/users</url>
    <host ip="93.184.216.34">example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/api/users</path>
    <request base64="true">R0VUIC9hcGkvdXNlcnMgSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQpBY2NlcHQ6IGFwcGxpY2F0aW9uL2pzb24NCg0K</request>
    <response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCg0KeyJpZCI6MX0=</response>
    <status>200</status>
  </item>
  <item>
    <url>http://example.com:8080/login</url>
    <host>example.com</host>
    <port>8080</port>
    <protocol>http</protocol>
    <method>POST</method>
    <path>/login</path>
    <request><![CDATA[POST /login HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 17

{"u":"a","p":"b"}]]></request>
    <status>302</status>
  </item>
</items>`

// writeTestFile writes content to a temp .xml file and returns its path.
func writeTestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "burp.xml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

func TestName(t *testing.T) {
	assert.Equal(t, "burpxml", New().Name())
}

func TestParse_MultipleItems(t *testing.T) {
	tmpFile := writeTestFile(t, testXML)

	f := New()
	var results []*httpmsg.HttpRequestResponse
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	require.Len(t, results, 2)

	// First item: base64 GET.
	req0 := results[0].Request()
	assert.Equal(t, "GET", req0.Method())
	assert.Equal(t, "example.com", results[0].Service().Host())
	assert.Equal(t, 443, results[0].Service().Port())
	assert.Contains(t, string(req0.Raw()), "/api/users")

	// Second item: raw POST on a non-standard port.
	req1 := results[1].Request()
	assert.Equal(t, "POST", req1.Method())
	assert.Equal(t, 8080, results[1].Service().Port())
	assert.Contains(t, string(req1.Raw()), `{"u":"a","p":"b"}`)
}

func TestParse_CallbackStopsEarly(t *testing.T) {
	tmpFile := writeTestFile(t, testXML)

	f := New()
	var count int
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		count++
		return false // stop after first
	})

	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestParse_SkipsEmptyRequest(t *testing.T) {
	xml := `<?xml version="1.0"?>
<items>
  <item>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <path>/empty</path>
    <request></request>
  </item>
  <item>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <path>/valid</path>
    <request><![CDATA[GET /valid HTTP/1.1
Host: example.com

]]></request>
  </item>
</items>`
	tmpFile := writeTestFile(t, xml)

	f := New()
	var results []*httpmsg.HttpRequestResponse
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, string(results[0].Request().Raw()), "/valid")
}

func TestParse_MissingFile(t *testing.T) {
	f := New()
	err := f.Parse(filepath.Join(t.TempDir(), "nope.xml"), func(rr *httpmsg.HttpRequestResponse) bool {
		return true
	})
	assert.Error(t, err)
}

func TestSetOptions(t *testing.T) {
	f := New()
	f.SetOptions(formats.InputFormatOptions{SkipFormatValidation: true})
	assert.True(t, f.formatOpts.SkipFormatValidation)
}

func TestCount(t *testing.T) {
	tmpFile := writeTestFile(t, testXML)

	count, err := New().Count(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestCount_MissingFile(t *testing.T) {
	_, err := New().Count(filepath.Join(t.TempDir(), "nope.xml"))
	assert.Error(t, err)
}

func TestBuildURL(t *testing.T) {
	// Standard port omitted, custom port included, missing host -> empty.
	assert.Equal(t, "https://example.com/api", buildURL(&burpItem{
		Host: burpHost{Value: "example.com"}, Port: 443, Protocol: "https", Path: "/api",
	}))
	assert.Equal(t, "http://example.com:8080/api", buildURL(&burpItem{
		Host: burpHost{Value: "example.com"}, Port: 8080, Protocol: "http", Path: "api",
	}))
	assert.Equal(t, "", buildURL(&burpItem{Port: 80, Protocol: "http"}))
	// Default protocol https, root path when none given.
	assert.Equal(t, "https://example.com/", buildURL(&burpItem{Host: burpHost{Value: "example.com"}}))
}

func TestDecodeContent(t *testing.T) {
	plain, err := decodeContent(&burpContent{Value: "GET / HTTP/1.1"})
	require.NoError(t, err)
	assert.Equal(t, "GET / HTTP/1.1", plain)

	decoded, err := decodeContent(&burpContent{Base64: "true", Value: "R0VUIC8gSFRUUC8xLjE="})
	require.NoError(t, err)
	assert.Equal(t, "GET / HTTP/1.1", decoded)

	_, err = decodeContent(&burpContent{Base64: "true", Value: "!!!not-base64!!!"})
	assert.Error(t, err)
}
