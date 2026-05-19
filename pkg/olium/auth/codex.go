// Package auth handles credential loading and refresh for olium's LLM
// providers. Each provider has its own on-disk format; this package keeps
// the formats byte-compatible with the vendor CLIs so users don't have to
// re-authenticate.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Codex OAuth constants — these match the official Codex CLI and pi-ai.
// DO NOT swap in your own client ID; the token endpoint validates it against
// the refresh token's issuer.
const (
	codexClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	codexTokenURL = "https://auth.openai.com/oauth/token"
	// JWT claim path where the access token carries ChatGPT account metadata.
	codexJWTClaimPath = "https://api.openai.com/auth"
	// Refresh proactively when the token is within this window of expiring.
	codexRefreshSkew = 60 * time.Second
	// Hard ceiling on a single refresh round-trip so a hung auth.openai.com
	// can't wedge the agent's first call.
	codexRefreshTimeout = 30 * time.Second
)

// errInvalidGrant signals that the OAuth server rejected our refresh_token.
// The most likely cause is that another process (codex CLI or another
// vigolium instance) already rotated it out from under us. The refresh
// path catches this, re-reads the on-disk file, and retries once with the
// fresh refresh token.
var errInvalidGrant = errors.New("codex refresh: invalid_grant")

// CodexAuthFile mirrors the on-disk shape of ~/.codex/auth.json.
type CodexAuthFile struct {
	AuthMode     string      `json:"auth_mode"`
	OpenAIAPIKey *string     `json:"OPENAI_API_KEY"`
	Tokens       CodexTokens `json:"tokens"`
	LastRefresh  string      `json:"last_refresh,omitempty"`
}

type CodexTokens struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id"`
}

// CodexAuth is the runtime handle used by the provider. It wraps the file
// and refreshes the access token on demand.
//
// Concurrency model:
//   - mu guards the in-memory file snapshot only; HTTP calls happen outside
//     the lock so peers don't serialize on the round-trip.
//   - sf coalesces concurrent refreshes — N goroutines hitting an expired
//     token result in a single POST to the OAuth endpoint.
//   - Cross-process safety (vigolium ↔ codex CLI) is handled by re-reading
//     auth.json from disk inside refreshOnce: if a peer rotated the tokens,
//     we adopt the fresh ones; if our refresh_token has been rotated out,
//     the OAuth server returns invalid_grant and we re-read + retry once.
type CodexAuth struct {
	path string

	mu   sync.Mutex
	file CodexAuthFile

	sf singleflight.Group

	// Overridable for tests.
	tokenURL   string
	httpClient *http.Client
}

// DefaultCodexAuthPath returns ~/.codex/auth.json.
func DefaultCodexAuthPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".codex", "auth.json"), nil
}

// LoadCodex reads the auth file at path. If path is empty, the default
// location is used.
func LoadCodex(path string) (*CodexAuth, error) {
	p, err := resolveCodexAuthPath(path)
	if err != nil {
		return nil, err
	}
	path = p

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read codex auth: %w", err)
	}

	var file CodexAuthFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse codex auth: %w", err)
	}
	if file.Tokens.AccessToken == "" {
		return nil, fmt.Errorf("codex auth at %s has no access token", path)
	}
	return &CodexAuth{
		path:       path,
		file:       file,
		tokenURL:   codexTokenURL,
		httpClient: &http.Client{Timeout: codexRefreshTimeout},
	}, nil
}

func resolveCodexAuthPath(path string) (string, error) {
	if path == "" {
		return DefaultCodexAuthPath()
	}

	path = os.ExpandEnv(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand codex auth path: %w", err)
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

// AccessToken returns a currently-valid access token, refreshing if needed.
// Concurrent callers coalesce on a singleflight group, so N parallel
// goroutines yield at most one OAuth POST.
func (c *CodexAuth) AccessToken(ctx context.Context) (string, error) {
	if tok, ok := c.cachedFreshToken(); ok {
		return tok, nil
	}
	return c.refreshAndGet(ctx, "")
}

// ForceRefresh discards the current cached token and obtains a new one.
// Use this when the upstream API rejected the cached token (HTTP 401)
// before its JWT exp claim said it should expire — clock skew, manual
// revocation, or server-side invalidation. Pass the rejected token so we
// can short-circuit if disk already holds a different (presumed-valid)
// token rotated in by a peer.
func (c *CodexAuth) ForceRefresh(ctx context.Context, rejectedToken string) (string, error) {
	return c.refreshAndGet(ctx, rejectedToken)
}

// AccountID returns the ChatGPT account ID from the access token claims.
// Falls back to the account_id field in the auth file if the claim is missing.
func (c *CodexAuth) AccountID() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if id, err := accountIDFromJWT(c.file.Tokens.AccessToken); err == nil && id != "" {
		return id, nil
	}
	if c.file.Tokens.AccountID != "" {
		return c.file.Tokens.AccountID, nil
	}
	return "", fmt.Errorf("no chatgpt_account_id in token claims or auth file")
}

func (c *CodexAuth) cachedFreshToken() (string, bool) {
	c.mu.Lock()
	tok := c.file.Tokens.AccessToken
	c.mu.Unlock()
	if tok == "" {
		return "", false
	}
	exp, err := jwtExpiry(tok)
	if err != nil {
		return "", false
	}
	if time.Until(exp) <= codexRefreshSkew {
		return "", false
	}
	return tok, true
}

func (c *CodexAuth) snapshotTokens() CodexTokens {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.file.Tokens
}

// refreshAndGet runs refreshOnce under singleflight and returns the fresh
// access token. The singleflight key is split between the time-based
// "refresh" path and the 401-driven "force-refresh" path so a benign
// no-op refresh in flight can't satisfy a caller that needs a real one.
func (c *CodexAuth) refreshAndGet(ctx context.Context, rejectedToken string) (string, error) {
	key := "refresh"
	if rejectedToken != "" {
		key = "force-refresh"
	}
	v, err, _ := c.sf.Do(key, func() (any, error) {
		if err := c.refreshOnce(ctx, rejectedToken); err != nil {
			return "", err
		}
		c.mu.Lock()
		tok := c.file.Tokens.AccessToken
		c.mu.Unlock()
		return tok, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// refreshOnce performs the disk re-read + adopt-or-POST + retry-on-stale
// dance described on the CodexAuth doc comment.
func (c *CodexAuth) refreshOnce(ctx context.Context, rejectedToken string) error {
	if err := c.reloadFromDisk(); err != nil {
		return err
	}
	snap := c.snapshotTokens()

	// Adopt-from-disk path: if a peer already refreshed and the disk's
	// access token is still fresh, we may not need to POST at all.
	//   - For the time-based path (rejectedToken == ""), any fresh disk
	//     token is good enough.
	//   - For the 401-driven path, only adopt if the disk token differs
	//     from the one the server just rejected.
	if snap.AccessToken != "" && snap.AccessToken != rejectedToken {
		if exp, err := jwtExpiry(snap.AccessToken); err == nil && time.Until(exp) > codexRefreshSkew {
			return nil
		}
	}

	if snap.RefreshToken == "" {
		return fmt.Errorf("codex access token expired and no refresh token available")
	}

	resp, err := c.postRefresh(ctx, snap.RefreshToken)
	if errors.Is(err, errInvalidGrant) {
		// The refresh_token we sent is no longer valid — most likely a
		// peer (codex CLI or another vigolium instance) refreshed and
		// the server rotated it. Re-read disk; if the on-disk
		// refresh_token differs, retry the POST once with the new one.
		if reloadErr := c.reloadFromDisk(); reloadErr != nil {
			return errors.Join(err, reloadErr)
		}
		newSnap := c.snapshotTokens()
		if newSnap.RefreshToken != "" && newSnap.RefreshToken != snap.RefreshToken {
			resp, err = c.postRefresh(ctx, newSnap.RefreshToken)
		}
	}
	if err != nil {
		return err
	}

	return c.persistTokens(resp)
}

// reloadFromDisk re-parses auth.json under the mutex. A missing or
// malformed file leaves the in-memory snapshot untouched and returns an
// error — callers may choose to proceed with the cached snapshot if they
// have one, or surface the error.
func (c *CodexAuth) reloadFromDisk() error {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return fmt.Errorf("reload codex auth: %w", err)
	}
	var file CodexAuthFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("reload codex auth: parse: %w", err)
	}
	c.mu.Lock()
	c.file = file
	c.mu.Unlock()
	return nil
}

type codexTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// postRefresh issues the OAuth refresh_token grant and returns the parsed
// response. A 400 with `error: "invalid_grant"` is converted to
// errInvalidGrant so the caller can retry with a re-read refresh_token.
func (c *CodexAuth) postRefresh(ctx context.Context, refreshToken string) (codexTokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {codexClientID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return codexTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return codexTokenResponse{}, fmt.Errorf("codex refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if isInvalidGrant(resp.StatusCode, body) {
			return codexTokenResponse{}, errInvalidGrant
		}
		return codexTokenResponse{}, fmt.Errorf("codex refresh failed (%d): %s", resp.StatusCode, string(body))
	}

	var out codexTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return codexTokenResponse{}, fmt.Errorf("codex refresh: decode response: %w", err)
	}
	if out.AccessToken == "" || out.RefreshToken == "" {
		return codexTokenResponse{}, fmt.Errorf("codex refresh: missing tokens in response")
	}
	return out, nil
}

func isInvalidGrant(status int, body []byte) bool {
	if status != http.StatusBadRequest && status != http.StatusUnauthorized {
		return false
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	return parsed.Error == "invalid_grant"
}

// persistTokens writes the refreshed tokens back to disk atomically. We
// write to a sibling .tmp file at 0600, then rename — POSIX-atomic, so a
// crash mid-write can never leave auth.json half-written.
func (c *CodexAuth) persistTokens(resp codexTokenResponse) error {
	c.mu.Lock()
	c.file.Tokens.AccessToken = resp.AccessToken
	c.file.Tokens.RefreshToken = resp.RefreshToken
	if resp.IDToken != "" {
		c.file.Tokens.IDToken = resp.IDToken
	}
	c.file.LastRefresh = time.Now().UTC().Format(time.RFC3339Nano)
	snapshot := c.file
	c.mu.Unlock()

	updated, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, updated, 0o600); err != nil {
		return fmt.Errorf("codex refresh: write tmp: %w", err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("codex refresh: rename: %w", err)
	}
	return nil
}

// --- JWT helpers (no signature verification — we only trust locally-stored tokens) ---

func jwtPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed jwt")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some issuers pad; try standard URL encoding.
		if raw, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return nil, fmt.Errorf("decode jwt payload: %w", err)
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("parse jwt payload: %w", err)
	}
	return claims, nil
}

func jwtExpiry(token string) (time.Time, error) {
	claims, err := jwtPayload(token)
	if err != nil {
		return time.Time{}, err
	}
	expRaw, ok := claims["exp"]
	if !ok {
		return time.Time{}, fmt.Errorf("no exp claim")
	}
	expFloat, ok := expRaw.(float64)
	if !ok {
		return time.Time{}, fmt.Errorf("exp not numeric")
	}
	return time.Unix(int64(expFloat), 0), nil
}

func accountIDFromJWT(token string) (string, error) {
	claims, err := jwtPayload(token)
	if err != nil {
		return "", err
	}
	authClaim, ok := claims[codexJWTClaimPath].(map[string]any)
	if !ok {
		return "", fmt.Errorf("no %s claim", codexJWTClaimPath)
	}
	id, _ := authClaim["chatgpt_account_id"].(string)
	if id == "" {
		return "", fmt.Errorf("no chatgpt_account_id")
	}
	return id, nil
}
