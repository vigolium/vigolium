package tls_cert_recon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// ---- pure-function unit tests -------------------------------------------

func TestIsCommonIssuer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		org, cn string
		want    bool
	}{
		{"DigiCert Inc", "DigiCert TLS RSA SHA256 2020 CA1", true},
		{"Let's Encrypt", "R3", true},
		{"", "ISRG Root X1", true},
		{"Cloudflare, Inc.", "Cloudflare Inc ECC CA-3", true},
		{"Google Trust Services LLC", "GTS CA 1C3", true},
		{"Sectigo Limited", "", true},
		{"Acme Internal CA", "Acme Root", false},
		{"", "corp-issuing-ca-01", false},
		{"", "", false},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, isCommonIssuer(c.org, c.cn), "issuer org=%q cn=%q", c.org, c.cn)
	}
}

func TestIsInternalHostname(t *testing.T) {
	t.Parallel()
	internal := []string{"app.internal", "db.corp", "host.local", "svc.lan", "intranet", "localhost", "*.dev.local"}
	for _, h := range internal {
		assert.Truef(t, isInternalHostname(h), "%q should be internal", h)
	}
	public := []string{"www.example.com", "api.staging.example.com", "cdn.example.org", ""}
	for _, h := range public {
		assert.Falsef(t, isInternalHostname(h), "%q should not be internal", h)
	}
}

func TestIsInternalIP(t *testing.T) {
	t.Parallel()
	internal := []string{"10.0.0.5", "192.168.1.1", "172.16.0.1", "127.0.0.1", "100.64.1.1", "169.254.0.1", "fd00::1", "::1"}
	for _, s := range internal {
		assert.Truef(t, isInternalIP(net.ParseIP(s)), "%q should be internal", s)
	}
	public := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	for _, s := range public {
		assert.Falsef(t, isInternalIP(net.ParseIP(s)), "%q should not be internal", s)
	}
	assert.False(t, isInternalIP(nil))
}

func TestClassifySANs(t *testing.T) {
	t.Parallel()
	b := classifySANs(
		"api.example.com",
		[]string{"www.example.com", "staging.example.com", "api.example.com", "host.corp", "other-company.com", "*.svc.example.com"},
		[]net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("8.8.8.8")},
		"cdn.example.com",
	)
	// In-scope: hosts under example.com, excluding the target itself.
	assert.ElementsMatch(t,
		[]string{"www.example.com", "staging.example.com", "svc.example.com", "cdn.example.com"},
		b.inScope)
	// Internal: non-public hostname + private IP. Loopback/public IPs and the
	// unrelated public domain are ignored.
	assert.ElementsMatch(t, []string{"host.corp", "10.0.0.5"}, b.internal)
}

// ---- end-to-end against live TLS servers --------------------------------

// TestScanPerHost_SelfSigned_Emits points the module at httptest's built-in
// self-signed certificate (issuer "Acme Co", SANs example.com + loopback IPs).
func TestScanPerHost_SelfSigned_Emits(t *testing.T) {
	t.Parallel()
	srv := startTLS(t) // no custom cert → httptest's default self-signed cert
	defer srv.Close()

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "a self-signed cert should produce one finding")
	assert.Equal(t, "self-signed", res[0].Metadata["cert_type"])
	assert.Equal(t, true, res[0].Metadata["self_signed"])
	assert.Contains(t, res[0].Info.Tags, "self-signed")
	// The loopback IP SANs (127.0.0.1 / ::1) are internal addresses.
	assert.NotEmpty(t, res[0].Metadata["internal_sans"])
	assert.Contains(t, res[0].Info.Tags, "internal-naming")
}

// TestScanPerHost_CommonCA_Skipped serves a cert chained to a "DigiCert"-named
// CA; a recognized public issuer must be skipped entirely.
func TestScanPerHost_CommonCA_Skipped(t *testing.T) {
	t.Parallel()
	cert := makeChain(t, "DigiCert Inc", "DigiCert TLS RSA CA G1", "shop.example.com",
		[]string{"shop.example.com", "api.internal"}, []net.IP{net.ParseIP("10.1.2.3")})
	srv := startTLS(t, cert)
	defer srv.Close()

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a certificate from a recognized public CA must be skipped")
}

// TestScanPerHost_PrivateCA_Emits serves a cert chained to an unrecognized
// internal CA; the leaf is not self-signed, so it is classified private-ca.
func TestScanPerHost_PrivateCA_Emits(t *testing.T) {
	t.Parallel()
	cert := makeChain(t, "Acme Internal CA", "Acme Issuing CA 01", "appliance",
		[]string{"appliance.corp", "mgmt.internal"}, []net.IP{net.ParseIP("10.0.0.9")})
	srv := startTLS(t, cert)
	defer srv.Close()

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "a private/internal-CA cert should produce one finding")
	assert.Equal(t, "private-ca", res[0].Metadata["cert_type"])
	assert.Equal(t, false, res[0].Metadata["self_signed"])
	// The single-label leaf CN ("appliance") is also harvested as an internal name.
	assert.ElementsMatch(t, []string{"appliance.corp", "mgmt.internal", "appliance", "10.0.0.9"}, res[0].Metadata["internal_sans"])
}

// TestScanPerHost_HTTPService_Skipped confirms a plain-HTTP service is never
// probed (no speculative 443 knock).
func TestScanPerHost_HTTPService_Skipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an http:// service must not be probed for TLS")
}

// ---- test helpers -------------------------------------------------------

// makeChain builds a leaf certificate signed by a freshly minted CA with the
// given issuer Organization/CN, returning a tls.Certificate carrying the leaf +
// CA chain so the leaf's issuer reflects the CA (not self-signed).
func makeChain(t *testing.T, caOrg, caCN, leafCN string, dnsNames []string, ips []net.IP) tls.Certificate {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{caOrg}, CommonName: caCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Example Org"}, CommonName: leafCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
	}
}

// startTLS starts an HTTPS test server. With no cert argument it uses httptest's
// default self-signed certificate; with one it presents that certificate. The
// server's error log is discarded because the module closes the connection right
// after the handshake (it only reads the cert), which the server would otherwise
// log as a noisy "use of closed network connection".
func startTLS(t *testing.T, certs ...tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	if len(certs) > 0 {
		srv.TLS = &tls.Config{Certificates: certs}
	}
	srv.StartTLS()
	return srv
}
