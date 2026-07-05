package xml_saml_security

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const signedSAML = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
	`<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example/</saml:Issuer>` +
	`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
	`<saml:Issuer>https://idp.example/</saml:Issuer>` +
	`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>` +
	`<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>` +
	`</saml:Assertion></samlp:Response>`

// samlDecode decodes the SAMLResponse query param the way the module re-encodes it
// (plain base64), tolerating a '+' that a form/query decode turned into a space.
func samlDecode(v string) string {
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(v, " ", "+"))
	if err != nil {
		return ""
	}
	return string(b)
}

// TestSignatureBypass_DetectsStripping: a vulnerable SP validates the assertion
// content (rejecting a wrong-issuer/NameID) but not the signature (accepting the
// signature-stripped assertion) — reported.
func TestSignatureBypass_DetectsStripping(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xml := samlDecode(r.URL.Query().Get("SAMLResponse"))
		if strings.Contains(xml, "vig-bogus") { // wrong identity/issuer → reject
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("access denied"))
			return
		}
		w.WriteHeader(http.StatusOK) // accepts regardless of signature presence
		_, _ = w.Write([]byte("Welcome, authenticated user — dashboard"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	value := base64.StdEncoding.EncodeToString([]byte(signedSAML))
	rr := modtest.Request(t, srv.URL+"/acs?SAMLResponse="+url.QueryEscape(value))
	ip := modtest.InsertionPoint(t, rr, "SAMLResponse")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected a SAML signature-stripping finding")
	assert.Contains(t, res[0].Info.Name, "Signature Not Verified")
}

// TestSignatureBypass_SecureSP: an SP that rejects an assertion missing its
// signature must not be flagged.
func TestSignatureBypass_SecureSP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xml := samlDecode(r.URL.Query().Get("SAMLResponse"))
		if !strings.Contains(xml, "Signature") || strings.Contains(xml, "vig-bogus") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("access denied"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome, authenticated user — dashboard"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	value := base64.StdEncoding.EncodeToString([]byte(signedSAML))
	rr := modtest.Request(t, srv.URL+"/acs?SAMLResponse="+url.QueryEscape(value))
	ip := modtest.InsertionPoint(t, rr, "SAMLResponse")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an SP that rejects unsigned assertions must not be flagged")
}

// TestSignatureBypass_AcceptsEverything: an SP that authenticates regardless of
// assertion content (accepts even the wrong-identity control) is not a signature
// bug — the bogus control suppresses the finding.
func TestSignatureBypass_AcceptsEverything(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome, authenticated user — dashboard"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	value := base64.StdEncoding.EncodeToString([]byte(signedSAML))
	rr := modtest.Request(t, srv.URL+"/acs?SAMLResponse="+url.QueryEscape(value))
	ip := modtest.InsertionPoint(t, rr, "SAMLResponse")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an SP that accepts any assertion (bogus control passes) must not be flagged")
}
