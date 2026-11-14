package ssrf_detection

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Suspect, m.Severity(), "Tentative implies Suspect")
	assert.Equal(t, severity.Tentative, m.Confidence())
	assert.Equal(t, modkit.ScanScopeInsertionPoint, m.ScanScopes())
}

func TestLooksLikeURLParam(t *testing.T) {
	tests := []struct {
		name      string
		paramName string
		value     string
		want      bool
		typ       httpmsg.InsertionPointType
	}{
		{"url name", "url", "anything", true, httpmsg.INS_PARAM_URL},
		{"uri name", "imageUri", "anything", true, httpmsg.INS_PARAM_URL},
		{"redirect name", "redirect_to", "/home", true, httpmsg.INS_PARAM_URL},
		{"callback name", "callback", "x", true, httpmsg.INS_PARAM_URL},
		{"proxy name", "proxyHost", "x", true, httpmsg.INS_PARAM_URL},
		{"http value", "q", "http://example.com", true, httpmsg.INS_PARAM_URL},
		{"https value", "q", "https://example.com", true, httpmsg.INS_PARAM_URL},
		{"scheme-relative value", "q", "//example.com/x", true, httpmsg.INS_PARAM_URL},
		{"plain name and value", "id", "12345", false, httpmsg.INS_PARAM_URL},
		{"name substring not url-ish", "username", "bob", false, httpmsg.INS_PARAM_URL},
		{"empty", "", "", false, httpmsg.INS_PARAM_URL},
		// Short names match only as whole tokens; a query param may share a header name.
		{"host query param", "host", "internal.example", true, httpmsg.INS_PARAM_URL},
		{"ghost is not host", "ghost", "boo", false, httpmsg.INS_PARAM_URL},
		{"context is not next", "context", "x", false, httpmsg.INS_PARAM_URL},
		// Standard request headers are never fetch sinks, however URL-like they look.
		{"host header", "Host", "internal.example", false, httpmsg.INS_HEADER},
		{"referer header with url value", "Referer", "https://site.example/login", false, httpmsg.INS_HEADER},
		{"origin header with url value", "Origin", "https://site.example", false, httpmsg.INS_HEADER},
		{"upgrade-insecure-requests substring-matches request", "Upgrade-Insecure-Requests", "1", false, httpmsg.INS_HEADER},
		{"user-agent header", "User-Agent", "Mozilla/5.0", false, httpmsg.INS_HEADER},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, looksLikeURLParam(tt.typ, tt.paramName, tt.value))
		})
	}
}

func TestCheckSSRFMarkers(t *testing.T) {
	markers := []string{"ami-id", "instance-id"}

	t.Run("marker present only in probe response fires", func(t *testing.T) {
		got := checkSSRFMarkers("... ami-id: 1234 ...", "<html>nothing here</html>", markers)
		assert.Equal(t, "ami-id", got)
	})

	t.Run("marker already in original body does not fire", func(t *testing.T) {
		// Critical false-positive guard: if the marker pre-existed in the
		// baseline response, it is not evidence of SSRF.
		got := checkSSRFMarkers("ami-id present", "the page already mentions ami-id", markers)
		assert.Equal(t, "", got)
	})

	t.Run("no marker present", func(t *testing.T) {
		got := checkSSRFMarkers("ordinary response", "ordinary baseline", markers)
		assert.Equal(t, "", got)
	})

	t.Run("case-insensitive match", func(t *testing.T) {
		got := checkSSRFMarkers("AMI-ID=abc", "", markers)
		assert.Equal(t, "ami-id", got)
	})
}

func TestPayloadsWellFormed(t *testing.T) {
	assert.NotEmpty(t, payloads, "payload table must not be empty")

	var sawAWSMetadata bool
	for i, p := range payloads {
		assert.NotEmpty(t, p.payload, "payload[%d] must have a payload string", i)
		assert.NotEmpty(t, p.markers, "payload[%d] (%s) must declare response markers", i, p.payload)
		assert.NotEmpty(t, p.desc, "payload[%d] (%s) must have a description", i, p.payload)
		for j, marker := range p.markers {
			assert.NotEmpty(t, marker, "payload[%d].markers[%d] must not be empty", i, j)
		}
		if strings.Contains(p.payload, "169.254.169.254") {
			sawAWSMetadata = true
		}
	}
	assert.True(t, sawAWSMetadata, "payload set should probe the cloud metadata IP 169.254.169.254")
}
