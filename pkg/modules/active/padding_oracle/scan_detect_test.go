package padding_oracle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// highEntropyBytes returns 32 deterministic high-entropy bytes (a sha256 digest)
// that DetectCiphertext accepts as ciphertext-shaped.
func highEntropyBytes(label string) []byte {
	h := sha256.Sum256([]byte("padding-oracle-test:" + label))
	return h[:32]
}

// markCryptoCBC returns a ScanContext with the host tagged crypto-cbc.
func markCryptoCBC(t *testing.T, rawURL string) *modkit.ScanContext {
	t.Helper()
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	sc.MarkTech(hostOf(t, rawURL), cbcTechTag)
	return sc
}

func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u.Host
}

// TestScanPerInsertionPoint_ExplicitErrorOracle models an AES-CBC endpoint that
// returns an explicit padding error for aligned ciphertext mutations, a distinct
// decode error for a malformed-encoding control, and a normal 200 for the clean
// value. Lane A must confirm a High/Firm finding.
func TestScanPerInsertionPoint_ExplicitErrorOracle(t *testing.T) {
	t.Parallel()
	seed := base64.StdEncoding.EncodeToString(highEntropyBytes("explicit"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := r.URL.Query().Get("d")
		switch {
		case strings.Contains(d, "!"):
			// Malformed encoding: fails to base64-decode BEFORE decryption.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("base64 decode error: illegal character in input"))
		case d == seed:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK: session accepted"))
		default:
			// Any validly-encoded but tampered ciphertext → padding error.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("javax.crypto.BadPaddingException: Given final block not properly padded"))
		}
	}))
	defer srv.Close()

	rawURL := srv.URL + "/?d=" + url.QueryEscape(seed)
	rr := modtest.Request(t, rawURL)
	ip := modtest.InsertionPoint(t, rr, "d")
	sc := markCryptoCBC(t, srv.URL)

	res, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), sc)
	require.NoError(t, err)
	require.Len(t, res, 1, "an explicit-error padding oracle must yield exactly one finding")

	f := res[0]
	assert.Equal(t, severity.High, f.Info.Severity)
	assert.Equal(t, severity.Firm, f.Info.Confidence)
	assert.Equal(t, "d", f.FuzzingParameter)
	assert.Equal(t, "explicit-error", f.Metadata["lane"])
	assert.Equal(t, "base64-std", f.Metadata["encoding"])
	assert.Equal(t, 16, f.Metadata["block_size"])
	assert.NotEmpty(t, f.AdditionalEvidence, "the finding must carry baseline/control/mutation evidence")
	assert.True(t, sc.TechStack.Has(hostOf(t, srv.URL), cbcTechTag))
}

// TestScanPerInsertionPoint_EncryptThenMAC models an encrypt-then-MAC endpoint
// that returns ONE uniform "invalid token" error for every tampered or malformed
// value (the MAC fails before any padding check). No finding must be produced.
func TestScanPerInsertionPoint_EncryptThenMAC(t *testing.T) {
	t.Parallel()
	seed := base64.StdEncoding.EncodeToString(highEntropyBytes("etm"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("d") == seed {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK: session accepted"))
			return
		}
		// Uniform generic error for mutations AND the malformed control alike.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("invalid token"))
	}))
	defer srv.Close()

	rawURL := srv.URL + "/?d=" + url.QueryEscape(seed)
	rr := modtest.Request(t, rawURL)
	ip := modtest.InsertionPoint(t, rr, "d")
	sc := markCryptoCBC(t, srv.URL)

	res, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), sc)
	require.NoError(t, err)
	assert.Empty(t, res, "an encrypt-then-MAC endpoint with a uniform error must not be flagged")
}

// TestScanPerInsertionPoint_BehavioralOracle models an oracle that distinguishes
// valid vs invalid padding by RESPONSE SHAPE (no explicit error string) and a
// separate decode-error class for malformed encoding. Lane B (deep) must confirm.
func TestScanPerInsertionPoint_BehavioralOracle(t *testing.T) {
	t.Parallel()
	seedBytes := highEntropyBytes("behavioral")
	seed := base64.StdEncoding.EncodeToString(seedBytes)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := r.URL.Query().Get("d")
		switch {
		case strings.Contains(d, "!"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("could not decode input"))
		case d == seed:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("valid session"))
		default:
			// Invalid padding, signalled behaviorally (no padding error string).
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte("request rejected"))
		}
	}))
	defer srv.Close()

	rawURL := srv.URL + "/?d=" + url.QueryEscape(seed)
	rr := modtest.Request(t, rawURL)
	ip := modtest.InsertionPoint(t, rr, "d")
	sc := markCryptoCBC(t, srv.URL)
	sc.DeepScan = true

	res, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), sc)
	require.NoError(t, err)
	require.Len(t, res, 1, "a behavioral padding oracle must be confirmed by the deep lane")
	assert.Equal(t, "behavioral", res[0].Metadata["lane"])
	assert.Equal(t, severity.High, res[0].Info.Severity)
	assert.Equal(t, severity.Firm, res[0].Info.Confidence)
}

// TestScanPerInsertionPoint_TechGateFailsClosed: without the crypto-cbc tech tag,
// even a genuine oracle target must not be probed.
func TestScanPerInsertionPoint_TechGateFailsClosed(t *testing.T) {
	t.Parallel()
	seed := base64.StdEncoding.EncodeToString(highEntropyBytes("gate"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := r.URL.Query().Get("d")
		switch {
		case strings.Contains(d, "!"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("decode error"))
		case d == seed:
			_, _ = w.Write([]byte("OK"))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("BadPaddingException"))
		}
	}))
	defer srv.Close()

	rawURL := srv.URL + "/?d=" + url.QueryEscape(seed)
	rr := modtest.Request(t, rawURL)
	ip := modtest.InsertionPoint(t, rr, "d")

	// TechStack present but crypto-cbc NOT marked → fail closed.
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	res, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), sc)
	require.NoError(t, err)
	assert.Empty(t, res, "the module must not run when crypto-cbc is not detected for the host")
}

func TestDetectCiphertext_Excludes(t *testing.T) {
	t.Parallel()

	// A JWT (three dot-separated segments) is not a raw ciphertext.
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhY21lIn0.c2lnbmF0dXJlLXZhbHVl"
	if _, ok := DetectCiphertext(jwt); ok {
		t.Errorf("DetectCiphertext accepted a JWT")
	}

	// A UUID is an identifier, not ciphertext.
	if _, ok := DetectCiphertext("550e8400-e29b-41d4-a716-446655440000"); ok {
		t.Errorf("DetectCiphertext accepted a UUID")
	}

	// A plain MD5/SHA-1/SHA-256 hex digest is a hash, not ciphertext.
	for _, h := range []string{
		hex.EncodeToString(highEntropyBytes("md5")[:16]),  // 32 hex
		hex.EncodeToString(highEntropyBytes("sha1")[:20]), // 40 hex
		hex.EncodeToString(highEntropyBytes("sha256")),    // 64 hex
	} {
		if _, ok := DetectCiphertext(h); ok {
			t.Errorf("DetectCiphertext accepted a plain hex digest %q", h)
		}
	}

	// A high-entropy but non-block-aligned blob (30 bytes) is rejected by the
	// block-size gate — the "random opaque token" case.
	opaque := base64.StdEncoding.EncodeToString(highEntropyBytes("opaque")[:30])
	if _, ok := DetectCiphertext(opaque); ok {
		t.Errorf("DetectCiphertext accepted a non-block-aligned opaque blob")
	}

	// A value that decodes to printable text/JSON is rejected.
	printable := base64.StdEncoding.EncodeToString([]byte(`{"user":"acme","role":"admin!"}`))
	if _, ok := DetectCiphertext(printable); ok {
		t.Errorf("DetectCiphertext accepted a value that decodes to printable JSON")
	}

	// Too short to be two blocks.
	if _, ok := DetectCiphertext("YWJj"); ok {
		t.Errorf("DetectCiphertext accepted a too-short value")
	}
}

func TestDetectCiphertext_URLSafeAndUnpadded(t *testing.T) {
	t.Parallel()

	// Find bytes whose base64 uses the URL-safe alphabet distinctively (so the
	// standard decoders fail and the URL decoders win, pinning the Encoding).
	var b []byte
	for i := 0; i < 10000; i++ {
		cand := highEntropyBytes(fmt.Sprintf("urlsafe-%d", i))
		u := base64.URLEncoding.EncodeToString(cand)
		if strings.ContainsAny(u, "-_") {
			b = cand
			break
		}
	}
	require.NotNil(t, b, "failed to derive URL-safe-distinct ciphertext bytes")

	t.Run("url-safe padded", func(t *testing.T) {
		c, ok := DetectCiphertext(base64.URLEncoding.EncodeToString(b))
		require.True(t, ok)
		assert.Equal(t, EncodingURLBase64, c.Encoding)
		assert.Equal(t, 16, c.BlockSize)
		assert.Equal(t, b, c.Decoded)
	})

	t.Run("url-safe unpadded", func(t *testing.T) {
		c, ok := DetectCiphertext(base64.RawURLEncoding.EncodeToString(b))
		require.True(t, ok)
		assert.Equal(t, EncodingRawURLBase64, c.Encoding)
		assert.Equal(t, 16, c.BlockSize)
		assert.Equal(t, b, c.Decoded)
	})

	t.Run("standard base64 round-trips via Reencode", func(t *testing.T) {
		std := base64.StdEncoding.EncodeToString(highEntropyBytes("std"))
		c, ok := DetectCiphertext(std)
		require.True(t, ok)
		assert.Equal(t, EncodingStdBase64, c.Encoding)
		assert.Equal(t, std, c.Reencode(c.Decoded), "Reencode must reproduce the original wire form")
	})
}

func TestFlipMutations(t *testing.T) {
	t.Parallel()
	dec := make([]byte, 32)
	// blockSize 16, 2 blocks. Penultimate block is [0,16); its last byte is index 15.

	m1 := FlipPenultimateLastByte(dec, 16)
	assert.Equal(t, byte(0x01), m1[15], "the low bit of the penultimate last byte must flip")
	m1[15] = 0
	assert.Equal(t, dec, m1, "no other byte may change")

	m2 := FlipPenultimateByteAt(dec, 16, 2)
	assert.Equal(t, byte(0x01), m2[14], "offset 2 must target the second-to-last byte of the penultimate block")

	// Out-of-range inputs (too short for two blocks) return an unchanged copy,
	// never panic.
	assert.Equal(t, dec[:8], FlipPenultimateByteAt(dec[:8], 16, 1))

	assert.True(t, strings.HasSuffix(MalformedControl("QUJD"), "!!"))
}
