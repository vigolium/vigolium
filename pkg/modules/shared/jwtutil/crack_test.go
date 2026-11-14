package jwtutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"testing"
)

// makeHS builds a compact JWT with the given alg header and HMAC signature over
// "header.payload" using secret and the provided hash constructor.
func makeHS(alg, secret string, newHash func() hash.Hash) string {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	header := b64(`{"alg":"` + alg + `","typ":"JWT"}`)
	payload := b64(`{"sub":"admin"}`)
	mac := hmac.New(newHash, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return header + "." + payload + "." + sig
}

func TestCrackHMACHit(t *testing.T) {
	cases := []struct {
		alg     string
		newHash func() hash.Hash
	}{
		{"HS256", sha256.New},
		{"HS384", sha512.New384},
		{"HS512", sha512.New},
	}
	for _, c := range cases {
		token := makeHS(c.alg, "s3cr3t", c.newHash)
		secrets := [][]byte{[]byte("nope"), []byte("s3cr3t"), []byte("other")}
		got, alg, ok := CrackHMAC(token, secrets)
		if !ok {
			t.Fatalf("%s: expected a crack, got none", c.alg)
		}
		if got != "s3cr3t" {
			t.Errorf("%s: recovered %q, want s3cr3t", c.alg, got)
		}
		if alg != c.alg {
			t.Errorf("%s: label %q, want %q", c.alg, alg, c.alg)
		}
	}
}

func TestCrackHMACMiss(t *testing.T) {
	token := makeHS("HS256", "rightone", sha256.New)
	if _, _, ok := CrackHMAC(token, [][]byte{[]byte("a"), []byte("b")}); ok {
		t.Error("expected no crack when the secret is absent from the list")
	}
}

func TestCrackHMACMalformed(t *testing.T) {
	for _, tok := range []string{"", "a.b", "notajwt", "a.b.c.d"} {
		if _, _, ok := CrackHMAC(tok, [][]byte{[]byte("x")}); ok {
			t.Errorf("expected no crack for malformed token %q", tok)
		}
	}
}

func TestCrackHMACUnsupportedAlg(t *testing.T) {
	// "none" and unknown algs are not HMAC-crackable.
	token := makeHS("none", "x", sha256.New)
	if _, _, ok := CrackHMAC(token, [][]byte{[]byte("x")}); ok {
		t.Error("expected no crack for alg=none")
	}
}

func TestCrackHMACAlgConfusion(t *testing.T) {
	// A token that declares RS256 but is actually HMAC-signed with a known secret
	// must crack via the algorithm-confusion path, labelled accordingly.
	token := makeHS("RS256", "publickey-as-secret", sha256.New)
	got, alg, ok := CrackHMAC(token, [][]byte{[]byte("publickey-as-secret")})
	if !ok || got != "publickey-as-secret" {
		t.Fatalf("expected alg-confusion crack, got ok=%v secret=%q", ok, got)
	}
	if alg == "RS256" || alg == "" {
		t.Errorf("expected an alg-confusion label, got %q", alg)
	}
}

// A genuine asymmetric token's signature cannot be an HMAC tag (wrong length),
// so no dictionary pass runs for it at all.
func TestCrackHMACSkipsImpossibleSignatureLengths(t *testing.T) {
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 256)) // RSA-2048 sized
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1"}`))
	before := dictionaryPasses.Load()
	if _, _, ok := CrackHMAC(hdr+"."+body+"."+sig, [][]byte{[]byte("a"), []byte("b")}); ok {
		t.Fatal("cracked an impossible signature")
	}
	if got := dictionaryPasses.Load() - before; got != 0 {
		t.Fatalf("dictionary passes = %d for a 256-byte signature, want 0", got)
	}
	before = dictionaryPasses.Load()
	CrackHMAC(makeHS("HS256", "x", sha256.New), [][]byte{[]byte("y")})
	if got := dictionaryPasses.Load() - before; got != 1 {
		t.Fatalf("dictionary passes = %d for HS256, want 1", got)
	}
}
