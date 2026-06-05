// Package mitm provides a self-signed certificate authority used by the ingest
// proxy to intercept TLS connections. The CA is generated once and persisted to
// disk (so it only has to be trusted once); per-host leaf certificates are
// minted on the fly during the TLS handshake and cached.
package mitm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	caCertFile = "vigolium-ca.pem"
	caKeyFile  = "vigolium-ca-key.pem"
)

// CA is a self-signed certificate authority. Use LoadOrCreateCA to obtain one,
// then TLSConfigForHost to terminate a client TLS connection while impersonating
// the requested host.
type CA struct {
	cert     *x509.Certificate // parsed CA certificate
	certDER  []byte            // raw DER of the CA cert (chained into every leaf)
	key      *ecdsa.PrivateKey // CA private key (signs leaves)
	certPath string            // on-disk path to the PEM cert (for export / trust)

	leafKey *ecdsa.PrivateKey // single private key reused by all leaves

	mu    sync.RWMutex
	cache map[string]*tls.Certificate // host -> minted leaf
}

// LoadOrCreateCA loads the CA from dir, generating and persisting a fresh one
// when it does not yet exist. The directory is created with 0700 perms; the CA
// private key is written 0600.
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create CA dir: %w", err)
	}
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	if ca, err := loadCA(certPath, keyPath); err == nil {
		return ca, nil
	}
	return generateCA(certPath, keyPath)
}

// loadCA reads an existing CA cert+key pair from disk.
func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if len(tlsCert.Certificate) == 0 {
		return nil, fmt.Errorf("empty CA certificate in %s", certPath)
	}
	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if !caCert.IsCA {
		return nil, fmt.Errorf("certificate in %s is not a CA", certPath)
	}
	caKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unexpected CA key type %T (want ECDSA)", tlsCert.PrivateKey)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:     caCert,
		certDER:  tlsCert.Certificate[0],
		key:      caKey,
		certPath: certPath,
		leafKey:  leafKey,
		cache:    make(map[string]*tls.Certificate),
	}, nil
}

// generateCA mints a fresh 10-year root CA and persists it.
func generateCA(certPath, keyPath string) (*CA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Vigolium Ingest Proxy CA",
			Organization: []string{"Vigolium"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // may sign leaf certs only, not sub-CAs
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return nil, err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:     caCert,
		certDER:  der,
		key:      caKey,
		certPath: certPath,
		leafKey:  leafKey,
		cache:    make(map[string]*tls.Certificate),
	}, nil
}

// CertPath returns the on-disk path of the PEM-encoded CA certificate. Clients
// trust this file (curl --cacert, OS/browser trust store) to verify the
// intercepted TLS connection.
func (c *CA) CertPath() string { return c.certPath }

// ExportCert copies the CA certificate PEM to dst (0644).
func (c *CA) ExportCert(dst string) error {
	data, err := os.ReadFile(c.certPath)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// TLSConfigForHost returns a tls.Config for terminating a client connection
// opened via CONNECT to connectHost. The leaf certificate is selected by SNI;
// when the client sends no SNI, connectHost is used as the fallback identity.
func (c *CA) TLSConfigForHost(connectHost string) *tls.Config {
	fallback := normalizeHost(connectHost)
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"}, // force HTTP/1.1 so requests parse with http.ReadRequest
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				host = fallback
			}
			return c.LeafFor(host)
		},
	}
}

// LeafFor returns a leaf certificate impersonating host, minting and caching it
// on first use.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("empty host for leaf certificate")
	}

	c.mu.RLock()
	cert, ok := c.cache[host]
	c.mu.RUnlock()
	if ok {
		return cert, nil
	}

	minted, err := c.mintLeaf(host)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Another goroutine may have raced us to mint the same host.
	if existing, ok := c.cache[host]; ok {
		return existing, nil
	}
	c.cache[host] = minted
	return minted, nil
}

// mintLeaf signs a fresh leaf certificate for host with the CA key.
func (c *CA) mintLeaf(host string) (*tls.Certificate, error) {
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// SAN is mandatory — modern clients reject certificates that carry the host
	// only in the CommonName.
	if ip := net.ParseIP(host); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, leaf, c.cert, &c.leafKey.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.certDER},
		PrivateKey:  c.leafKey,
	}, nil
}

// randSerial returns a random 128-bit positive serial number.
func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// writePEM PEM-encodes der and writes it atomically with the given perms.
func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return err
	}
	if err := os.WriteFile(path, buf.Bytes(), perm); err != nil {
		return err
	}
	// WriteFile only applies perm on creation; tighten unconditionally so a
	// pre-existing key file can't keep looser permissions.
	return os.Chmod(path, perm)
}

// normalizeHost strips any port and trailing dot and lowercases the host.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
