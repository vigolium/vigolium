package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadCodexExpandsHomePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := filepath.Join(home, ".codex", "auth.json")
	writeCodexAuthFile(t, path, "access-token", "refresh-token")

	auth, err := LoadCodex("~/.codex/auth.json")
	if err != nil {
		t.Fatalf("LoadCodex returned error: %v", err)
	}
	if auth.path != path {
		t.Fatalf("LoadCodex path = %q, want %q", auth.path, path)
	}
}

func TestLoadCodexExpandsEnvVars(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CODEX_AUTH_DIR", dir)

	path := filepath.Join(dir, "auth.json")
	writeCodexAuthFile(t, path, "access-token", "refresh-token")

	auth, err := LoadCodex("$CODEX_AUTH_DIR/auth.json")
	if err != nil {
		t.Fatalf("LoadCodex returned error: %v", err)
	}
	if auth.path != path {
		t.Fatalf("LoadCodex path = %q, want %q", auth.path, path)
	}
}

// Another process (codex CLI or a peer vigolium) refreshed the tokens on
// disk while we were sitting on an expired cached copy. AccessToken should
// re-read auth.json, find the fresh disk token, and adopt it without
// calling the OAuth endpoint.
func TestAccessTokenAdoptsExternallyRefreshedToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	expired := makeJWT(t, time.Now().Add(-time.Hour))
	writeCodexAuthFileWithJWT(t, path, expired, "old-refresh")

	auth, err := LoadCodex(path)
	if err != nil {
		t.Fatalf("LoadCodex: %v", err)
	}

	var posted int32
	auth.tokenURL = "" // any POST should fail loudly
	auth.httpClient = &http.Client{Transport: failingTransport(&posted)}

	freshAccess := makeJWT(t, time.Now().Add(2*time.Hour))
	writeCodexAuthFileWithJWT(t, path, freshAccess, "new-refresh")

	tok, err := auth.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if tok != freshAccess {
		t.Fatalf("AccessToken = %q, want freshly-adopted disk token", tok)
	}
	if got := atomic.LoadInt32(&posted); got != 0 {
		t.Fatalf("expected 0 OAuth POSTs, got %d", got)
	}
}

// Our cached refresh_token has already been rotated out by a peer. The
// first POST returns invalid_grant; refreshOnce must re-read disk and
// retry once with the new refresh_token.
func TestRefreshRetriesAfterInvalidGrant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	expired := makeJWT(t, time.Now().Add(-time.Hour))
	writeCodexAuthFileWithJWT(t, path, expired, "stale-refresh")

	var posts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got := r.FormValue("refresh_token")
		n := atomic.AddInt32(&posts, 1)
		if n == 1 {
			if got != "stale-refresh" {
				t.Errorf("first POST refresh_token = %q, want stale-refresh", got)
			}
			// Simulate a peer rotating the refresh_token mid-flight by
			// writing the new value to disk before we return the
			// invalid_grant error.
			writeCodexAuthFileWithJWT(t, path, expired, "fresh-refresh")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"rotated"}`))
			return
		}
		if got != "fresh-refresh" {
			t.Errorf("second POST refresh_token = %q, want fresh-refresh", got)
		}
		newAccess := makeJWT(t, time.Now().Add(2*time.Hour))
		_ = json.NewEncoder(w).Encode(codexTokenResponse{
			AccessToken:  newAccess,
			RefreshToken: "even-fresher-refresh",
			ExpiresIn:    3600,
		})
	}))
	defer srv.Close()

	auth, err := LoadCodex(path)
	if err != nil {
		t.Fatalf("LoadCodex: %v", err)
	}
	auth.tokenURL = srv.URL
	auth.httpClient = srv.Client()

	tok, err := auth.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if tok == "" {
		t.Fatal("AccessToken returned empty token")
	}
	if got := atomic.LoadInt32(&posts); got != 2 {
		t.Fatalf("expected 2 POSTs (initial + retry), got %d", got)
	}

	// Disk should now hold the rotated refresh_token from the second POST.
	raw, _ := os.ReadFile(path)
	var on CodexAuthFile
	_ = json.Unmarshal(raw, &on)
	if on.Tokens.RefreshToken != "even-fresher-refresh" {
		t.Fatalf("disk refresh_token = %q, want even-fresher-refresh", on.Tokens.RefreshToken)
	}
}

// N concurrent goroutines hitting an expired token must coalesce to a
// single OAuth POST via singleflight — otherwise we'd hammer the OAuth
// endpoint with `max_concurrent` agent calls every refresh window.
func TestSingleflightCoalescesConcurrentRefresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	expired := makeJWT(t, time.Now().Add(-time.Hour))
	writeCodexAuthFileWithJWT(t, path, expired, "refresh-1")

	var posts int32
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		<-gate // hold the response until all callers have arrived
		newAccess := makeJWT(t, time.Now().Add(2*time.Hour))
		_ = json.NewEncoder(w).Encode(codexTokenResponse{
			AccessToken:  newAccess,
			RefreshToken: "refresh-2",
			ExpiresIn:    3600,
		})
	}))
	defer srv.Close()

	auth, err := LoadCodex(path)
	if err != nil {
		t.Fatalf("LoadCodex: %v", err)
	}
	auth.tokenURL = srv.URL
	auth.httpClient = srv.Client()

	const N = 10
	var wg sync.WaitGroup
	tokens := make([]string, N)
	errs := make([]error, N)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = auth.AccessToken(context.Background())
		}(i)
	}

	// Give the goroutines a moment to all enter singleflight.
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
		if tokens[i] == "" {
			t.Fatalf("goroutine %d: empty token", i)
		}
		if tokens[i] != tokens[0] {
			t.Fatalf("goroutine %d: token mismatch", i)
		}
	}
	if got := atomic.LoadInt32(&posts); got != 1 {
		t.Fatalf("expected exactly 1 OAuth POST (singleflight), got %d", got)
	}
}

// After a successful refresh, no .tmp sibling should be left behind —
// proves the rename happened.
func TestRefreshLeavesNoTmpFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	expired := makeJWT(t, time.Now().Add(-time.Hour))
	writeCodexAuthFileWithJWT(t, path, expired, "refresh-1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newAccess := makeJWT(t, time.Now().Add(2*time.Hour))
		_ = json.NewEncoder(w).Encode(codexTokenResponse{
			AccessToken:  newAccess,
			RefreshToken: "refresh-2",
			ExpiresIn:    3600,
		})
	}))
	defer srv.Close()

	auth, err := LoadCodex(path)
	if err != nil {
		t.Fatalf("LoadCodex: %v", err)
	}
	auth.tokenURL = srv.URL
	auth.httpClient = srv.Client()

	if _, err := auth.AccessToken(context.Background()); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}

	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected no .tmp sibling, stat err = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read auth.json: %v", err)
	}
	var on CodexAuthFile
	if err := json.Unmarshal(raw, &on); err != nil {
		t.Fatalf("auth.json invalid JSON: %v", err)
	}
	if on.Tokens.RefreshToken != "refresh-2" {
		t.Fatalf("disk refresh_token = %q, want refresh-2", on.Tokens.RefreshToken)
	}
}

// --- helpers ---

func writeCodexAuthFile(t *testing.T, path, access, refresh string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	body := fmt.Sprintf(`{"tokens":{"access_token":%q,"refresh_token":%q,"account_id":"acct"}}`, access, refresh)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func writeCodexAuthFileWithJWT(t *testing.T, path, accessJWT, refresh string) {
	t.Helper()
	writeCodexAuthFile(t, path, accessJWT, refresh)
}

// makeJWT crafts an unsigned (alg:none) JWT carrying the given exp claim.
// CodexAuth never validates the signature — it only reads the exp and the
// account-id claim — so an unsigned token is sufficient for tests.
func makeJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]any{
		"exp": exp.Unix(),
		codexJWTClaimPath: map[string]any{
			"chatgpt_account_id": "acct-test",
		},
	})
	if err != nil {
		t.Fatalf("marshal jwt payload: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return header + "." + body + "." + sig
}

// failingTransport increments the counter on every request and returns an
// error — used to assert "no POST should happen".
func failingTransport(counter *int32) http.RoundTripper {
	return roundTripperFunc(func(*http.Request) (*http.Response, error) {
		atomic.AddInt32(counter, 1)
		return nil, fmt.Errorf("unexpected OAuth POST")
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
