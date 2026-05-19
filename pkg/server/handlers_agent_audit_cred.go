package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// byokCredDirName is the subdirectory under the configured sessions dir
// where the server stages inline cred JSON for the lifetime of one
// audit run. Kept under sessions_dir (not /tmp) so artifact retention,
// disk-usage tracking, and operator audits all see the same surface.
const byokCredDirName = "byok-creds"

// stageInlineCredJSON parses cred JSON, validates it has at least the
// shape of a real Codex auth.json (a tokens object), and writes it to a
// per-request 0600 temp file under <sessions_dir>/byok-creds/. Returns
// the absolute file path and a cleanup func that removes it.
//
// On parse failure or shape mismatch returns a non-nil error and no
// cleanup; the caller surfaces this as a 400 to the client.
func stageInlineCredJSON(sessionsDir, raw string) (path string, cleanup func(), err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", func() {}, nil
	}

	var parsed map[string]any
	if jsonErr := json.Unmarshal([]byte(raw), &parsed); jsonErr != nil {
		return "", nil, fmt.Errorf("oauth_cred_json: invalid JSON: %w", jsonErr)
	}
	// Codex auth.json must have a `tokens` object (id_token, access_token,
	// refresh_token, account_id). We don't require every subfield — that's
	// the codex provider's job — but a missing `tokens` is almost always
	// a copy-paste mistake (e.g. pasting an API key instead of a JSON).
	if _, ok := parsed["tokens"].(map[string]any); !ok {
		return "", nil, fmt.Errorf("oauth_cred_json: missing 'tokens' object — pass the contents of `codex login`'s auth.json, not a bare key")
	}

	dir := filepath.Join(sessionsDir, byokCredDirName)
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		return "", nil, fmt.Errorf("oauth_cred_json: prepare staging dir: %w", mkErr)
	}

	// uuid-based filename so two concurrent requests never collide; also
	// makes it grep-able alongside the AgenticScan UUID in logs.
	name := "byok-" + uuid.NewString() + ".json"
	path = filepath.Join(dir, name)

	// O_EXCL guards against a vanishingly-unlikely UUID collision.
	f, openErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if openErr != nil {
		return "", nil, fmt.Errorf("oauth_cred_json: stage file: %w", openErr)
	}
	if _, writeErr := f.Write([]byte(raw)); writeErr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("oauth_cred_json: write staged file: %w", writeErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("oauth_cred_json: finalize staged file: %w", closeErr)
	}

	cleanup = func() {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			zap.L().Warn("oauth_cred_json: failed to remove staged file",
				zap.String("path", path), zap.Error(rmErr))
		}
	}
	return path, cleanup, nil
}
