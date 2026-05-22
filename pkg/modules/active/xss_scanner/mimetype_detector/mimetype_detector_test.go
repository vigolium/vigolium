package mimetype_detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractRawContentTypeHeaders(t *testing.T) {
	// Case-insensitive key match; the last matching value wins.
	headers := map[string]string{
		"content-type": "text/html",
	}
	assert.Equal(t, "text/html", ExtractRawContentTypeHeaders(headers))

	headers2 := map[string]string{
		"Content-Type": "application/json; charset=utf-8",
		"X-Other":      "ignored",
	}
	assert.Equal(t, "application/json; charset=utf-8", ExtractRawContentTypeHeaders(headers2))
}

func TestExtractCharsetFromSingleHeader(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"text/html; charset=utf-8", "utf-8"},
		{"text/html;charset=ISO-8859-1", "iso-8859-1"},
		{"application/json ; charset = UTF-16 ", "utf-16"},
		{"text/html", ""},
		{"", ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ExtractCharsetFromSingleHeader(tc.in), "input %q", tc.in)
	}
}

func TestExtractCharset(t *testing.T) {
	assert.Equal(t, "utf-8", ExtractCharset("text/html; charset=utf-8"))
	assert.Equal(t, "", ExtractCharset("text/html"))
}

func TestGetStatedInferredContentType(t *testing.T) {
	cases := []struct {
		name      string
		header    string
		wantMime  string
		wantShort ContentType
	}{
		{"html", "text/html", "text/html", ContentType_HTML},
		{"html with charset", "text/html; charset=utf-8", "text/html", ContentType_HTML},
		{"plain text", "text/plain", "text/plain", ContentType_PLAIN_TEXT},
		{"css", "text/css", "text/css", ContentType_CSS},
		{"javascript app", "application/javascript", "application/javascript", ContentType_SCRIPT},
		{"javascript text", "text/javascript", "text/javascript", ContentType_SCRIPT},
		{"json", "application/json", "application/json", ContentType_JSON},
		{"json variant", "application/problem+json", "application/problem+json", ContentType_JSON},
		{"xml", "application/xml", "application/xml", ContentType_XML},
		{"xml variant", "application/atom+xml", "application/atom+xml", ContentType_XML},
		{"rtf", "application/rtf", "application/rtf", ContentType_RTF},
		{"yaml", "application/yaml", "application/yaml", ContentType_YAML},
		{"yaml x variant", "application/x-yaml", "application/x-yaml", ContentType_YAML},
		{"yml partial", "text/x-yml", "text/x-yml", ContentType_YAML},
		{"svg full", "image/svg+xml", "image/svg+xml", ContentType_SVG},
		{"uppercase normalized", "TEXT/HTML", "text/html", ContentType_HTML},
		{"unrecognized", "application/octet-stream", "application/octet-stream", ContentType_UNRECOGNIZED_CONTENT},
		{"empty header", "", "", ContentType_NONE},
		{"only charset param", "; charset=utf-8", "", ContentType_NONE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mime, short := GetStatedInferredContentType(tc.header)
			assert.Equal(t, tc.wantMime, mime)
			assert.Equal(t, tc.wantShort, short)
		})
	}
}

func TestGetInferredContentType(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want ContentType
	}{
		{"empty body", []byte(""), ContentType_NONE},
		{"html doc", []byte("<!DOCTYPE html><html><body>hi</body></html>"), ContentType_HTML},
		{"plain text", []byte("just some plain text content"), ContentType_PLAIN_TEXT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, GetInferredContentType(tc.body))
		})
	}
}

func TestParseIsNoSniff(t *testing.T) {
	assert.True(t, ParseIsNoSniff(map[string]string{"X-Content-Type-Options": "nosniff"}))
	assert.True(t, ParseIsNoSniff(map[string]string{"x-content-type-options": "NoSniff"}))
	assert.False(t, ParseIsNoSniff(map[string]string{"X-Content-Type-Options": "other"}))
	assert.False(t, ParseIsNoSniff(map[string]string{}))
}

func TestParseIsAttachment(t *testing.T) {
	assert.True(t, ParseIsAttachment(map[string]string{"Content-Disposition": "attachment; filename=x.zip"}))
	assert.True(t, ParseIsAttachment(map[string]string{"content-disposition": "ATTACHMENT"}))
	assert.False(t, ParseIsAttachment(map[string]string{"Content-Disposition": "inline"}))
	assert.False(t, ParseIsAttachment(map[string]string{}))
}

// TestMimetypeDetectorGetters exercises the zero-value getters so callers can
// rely on nil-safe slice returns and default scalar values.
func TestMimetypeDetectorGetters(t *testing.T) {
	md := &MimetypeDetector{}
	assert.Equal(t, ContentType_NONE, md.GetStatedType())
	assert.Equal(t, ContentType_NONE, md.GetInferredType())
	assert.False(t, md.GetIsNoSniff())
	assert.False(t, md.GetIsAttachment())

	raw := md.GetRawContentTypeHeaderValues()
	require.NotNil(t, raw)
	assert.Empty(t, raw)

	charsets := md.GetCharsetHeaderValues()
	require.NotNil(t, charsets)
	assert.Empty(t, charsets)

	// Populated detector returns copies (mutating the copy must not affect state).
	populated := &MimetypeDetector{
		rawContentTypeHeaderValues: []string{"text/html"},
		charsetHeaderValues:        []string{"utf-8"},
		statedType:                 ContentType_HTML,
		inferredType:               ContentType_HTML,
		isNoSniff:                  true,
		isAttachment:               true,
	}
	assert.Equal(t, ContentType_HTML, populated.GetStatedType())
	assert.Equal(t, ContentType_HTML, populated.GetInferredType())
	assert.True(t, populated.GetIsNoSniff())
	assert.True(t, populated.GetIsAttachment())

	gotRaw := populated.GetRawContentTypeHeaderValues()
	gotRaw[0] = "mutated"
	assert.Equal(t, "text/html", populated.GetRawContentTypeHeaderValues()[0])

	gotCharsets := populated.GetCharsetHeaderValues()
	gotCharsets[0] = "mutated"
	assert.Equal(t, "utf-8", populated.GetCharsetHeaderValues()[0])
}
