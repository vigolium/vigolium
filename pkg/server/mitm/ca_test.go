package mitm

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateCA_GeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	// Both files must exist, with the key locked down to 0600.
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert not written: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key perms = %o, want 600", perm)
	}

	if !ca.cert.IsCA {
		t.Error("generated cert is not a CA")
	}
	if ca.cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert missing CertSign key usage")
	}
	if ca.CertPath() != certPath {
		t.Errorf("CertPath() = %q, want %q", ca.CertPath(), certPath)
	}
}

func TestLoadOrCreateCA_ReusesExisting(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreateCA: %v", err)
	}
	second, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateCA: %v", err)
	}

	// A reload must return the SAME persisted CA, not mint a new one — otherwise
	// the user would have to re-trust the CA on every server restart.
	if first.cert.SerialNumber.Cmp(second.cert.SerialNumber) != 0 {
		t.Errorf("CA serial changed across reload: %s vs %s",
			first.cert.SerialNumber, second.cert.SerialNumber)
	}
}

func TestLeafFor_SANChainAndCache(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	t.Run("dns host", func(t *testing.T) {
		leaf, err := ca.LeafFor("api.example.com")
		if err != nil {
			t.Fatalf("LeafFor: %v", err)
		}
		cert, err := x509.ParseCertificate(leaf.Certificate[0])
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		// SAN must carry the host (CN-only certs are rejected by modern clients)
		// and the leaf must chain to the CA for the right hostname + EKU.
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: "api.example.com", Roots: roots}); err != nil {
			t.Fatalf("leaf does not verify against CA: %v", err)
		}
	})

	t.Run("ip host", func(t *testing.T) {
		leaf, err := ca.LeafFor("127.0.0.1")
		if err != nil {
			t.Fatalf("LeafFor: %v", err)
		}
		cert, err := x509.ParseCertificate(leaf.Certificate[0])
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		if len(cert.IPAddresses) == 0 {
			t.Fatal("IP host leaf missing IP SAN")
		}
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: roots}); err != nil {
			t.Fatalf("IP leaf does not verify: %v", err)
		}
	})

	t.Run("cached and port-normalized", func(t *testing.T) {
		a, _ := ca.LeafFor("cache.example.com")
		b, _ := ca.LeafFor("cache.example.com:443") // port stripped → same cache entry
		if a != b {
			t.Error("expected identical cached leaf for host with and without port")
		}
	})
}
