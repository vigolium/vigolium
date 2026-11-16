package aspnet_viewstate_detect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// makeHTMLCtx builds a text/html request/response pair carrying the given body.
func makeHTMLCtx(path, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s", body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_UnencryptedViewState drives a postback form with a valid,
// unencrypted base64 __VIEWSTATE and no EventValidation / anti-CSRF token. This
// exercises the unencrypted, missing-EventValidation, and missing-CSRF paths.
func TestScanPerRequest_UnencryptedViewState(t *testing.T) {
	t.Parallel()
	m := New()
	// Valid base64 opening with the ObjectStateFormatter header (FF 01): unencrypted.
	vs := "/wEOFgICtaqCAQK+veGyDVVmd4iZqrvM"
	body := fmt.Sprintf(`<html><form method="post"><input type="hidden" name="__VIEWSTATE" value="%s" /></form></html>`, vs)
	ctx := makeHTMLCtx("/page.aspx", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		assert.Equal(t, ModuleID, r.ModuleID)
		if r.Info.Name == "ASP.NET ViewState Not Encrypted" {
			found = true
		}
	}
	assert.True(t, found, "expected unencrypted ViewState finding")
}

// TestScanPerRequest_NoViewState verifies a plain HTML page without ViewState
// yields no findings.
func TestScanPerRequest_NoViewState(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTMLCtx("/", `<html><body>Hello World</body></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonHTML verifies non-HTML responses are skipped even when
// the body mentions __VIEWSTATE.
func TestScanPerRequest_NonHTML(t *testing.T) {
	t.Parallel()
	m := New()
	rawReq := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"__VIEWSTATE\":\"x\"}"))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// msDocsValidationKey is the example key of Microsoft's protected-configuration
// walkthrough, the embedded list's entry.
const msDocsValidationKey = "D61B3C89CB33A2F1422FF158AFF7320E8DB8CB5CDA1742572A487D94018787EF42682B202B746511891C1BAF47F8D25C07F6C39A104696DB51F17C529AD3CABE"

// legacyViewState signs a serialized ViewState the way ASP.NET's legacy MAC
// does: serialized || HMAC-SHA256(key, serialized || generator as 4 LE bytes).
func legacyViewState(t *testing.T, keyHex, generator string) string {
	t.Helper()
	key, err := hex.DecodeString(keyHex)
	require.NoError(t, err)
	gen, err := strconv.ParseUint(generator, 16, 32)
	require.NoError(t, err)
	modifier := binary.LittleEndian.AppendUint32(nil, uint32(gen))
	serialized := []byte{0xFF, 0x01, 0x0F, 0x0F, 0x05, 0x0A, 0x2D, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x64, 0x64}
	mac := hmac.New(sha256.New, key)
	mac.Write(serialized)
	mac.Write(modifier)
	return base64.StdEncoding.EncodeToString(append(serialized, mac.Sum(nil)...))
}

func viewStatePage(vs, generator string) string {
	return fmt.Sprintf(`<html><form method="post" action="./Default.aspx">`+
		`<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="%s" />`+
		`<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="%s" />`+
		`<input type="hidden" name="__EVENTVALIDATION" value="x" /><input name="__RequestVerificationToken" value="y" /></form></html>`, vs, generator)
}

func knownKeyResult(results []*output.ResultEvent) *output.ResultEvent {
	for _, r := range results {
		if r.Info.Name == "ASP.NET ViewState Signed with a Published machineKey" {
			return r
		}
	}
	return nil
}

// A ViewState whose MAC recomputes under the embedded Microsoft Docs key is a
// critical deserialization finding that names the key's source.
func TestScanPerRequest_KnownMachineKey(t *testing.T) {
	t.Parallel()
	ctx := makeHTMLCtx("/Default.aspx", viewStatePage(legacyViewState(t, msDocsValidationKey, "CA0B0334"), "CA0B0334"))
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	hit := knownKeyResult(results)
	require.NotNil(t, hit, "a ViewState signed with a published key must be reported")
	assert.Equal(t, severity.Critical, hit.Info.Severity)
	assert.Equal(t, "deserialization", hit.VulnClass)
	assert.Equal(t, "HMACSHA256", hit.Metadata["validation_algorithm"])
	assert.Contains(t, hit.Metadata["key_source"], "Microsoft Docs")
	assert.Equal(t, false, hit.Metadata["purpose_based_mac_tested"], "the finding says what it did not check")
}

// An unlisted key, a different generator, or no generator never matches.
func TestScanPerRequest_KnownMachineKeyMisses(t *testing.T) {
	t.Parallel()
	unlisted := "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
	for name, body := range map[string]string{
		"unlisted key":      viewStatePage(legacyViewState(t, unlisted, "CA0B0334"), "CA0B0334"),
		"other generator":   viewStatePage(legacyViewState(t, msDocsValidationKey, "CA0B0334"), "0000ABCD"),
		"missing generator": strings.Replace(viewStatePage(legacyViewState(t, msDocsValidationKey, "CA0B0334"), "CA0B0334"), "__VIEWSTATEGENERATOR", "__OTHER", 2),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			results, err := New().ScanPerRequest(makeHTMLCtx("/Default.aspx", body), &modkit.ScanContext{})
			require.NoError(t, err)
			assert.Nil(t, knownKeyResult(results))
		})
	}
}

// TestScanPerRequest_ViewStateHeaderDecidesEncryption pins the encryption test
// to the ObjectStateFormatter header: /wEP and /wEQ (FF 01 0F, FF 01 10) are the
// commonest unencrypted ViewStates, and bytes without the header are ciphertext.
func TestScanPerRequest_ViewStateHeaderDecidesEncryption(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		vs          string
		unencrypted bool
	}{
		{"pair token /wEP", "/wEPDwUKLTkxNjM4NzE1N2RkZmFrZW1hY2J5dGVz", true},
		{"triplet token /wEQ", "/wEQDwUKLTkxNjM4NzE1N2RkZmFrZW1hY2J5dGVz", true},
		{"ciphertext without header", "q83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNF", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := fmt.Sprintf(`<html><input type="hidden" name="__VIEWSTATE" value="%s" /><input name="__EVENTVALIDATION" value="x"/></html>`, tc.vs)
			results, err := New().ScanPerRequest(makeHTMLCtx("/p.aspx", body), &modkit.ScanContext{})
			require.NoError(t, err)
			found := false
			for _, r := range results {
				if r.Info.Name == "ASP.NET ViewState Not Encrypted" {
					found = true
				}
			}
			assert.Equal(t, tc.unencrypted, found)
		})
	}
}
