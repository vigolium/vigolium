package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// vertexCloudPlatformScope is the OAuth2 scope required to call any Vertex AI
// endpoint (publishers/google or publishers/anthropic). The narrower
// `aiplatform.googleapis.com/auth/aiplatform` scope also works but isn't
// universally accepted across all Anthropic-on-Vertex endpoints, so we stick
// with the standard cloud-platform scope.
const vertexCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// VertexAuth holds a parsed GCP service-account JSON file and a token source
// that mints (and caches/refreshes) GCP access tokens on demand. The token
// source is built once and is safe for concurrent use.
type VertexAuth struct {
	path      string
	projectID string

	mu          sync.Mutex
	tokenSource oauth2.TokenSource
}

// LoadVertex reads a GCP service-account JSON file and returns an auth
// handle. If path is empty, $GOOGLE_APPLICATION_CREDENTIALS is consulted.
// Returns an error if neither is set or the file cannot be parsed.
func LoadVertex(path string) (*VertexAuth, error) {
	resolved, err := resolveVertexAuthPath(path)
	if err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("read vertex sa: %w", err)
	}

	// CredentialsFromJSON handles both legacy service-account JSON files and
	// newer external-account / federated-credential formats. JWTConfigFromJSON
	// would only handle the classic SA shape — pick the broader option.
	creds, err := google.CredentialsFromJSON(context.Background(), raw, vertexCloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("parse vertex sa: %w", err)
	}

	// project_id from the SA file is the last-resort fallback for the project
	// resolution chain. We extract it eagerly so it's available without a
	// network round-trip.
	projectID := creds.ProjectID
	if projectID == "" {
		// CredentialsFromJSON only fills ProjectID when the credential type
		// is service_account. Parse the file directly as a fallback.
		var probe struct {
			ProjectID string `json:"project_id"`
		}
		_ = json.Unmarshal(raw, &probe)
		projectID = probe.ProjectID
	}

	return &VertexAuth{
		path:        resolved,
		projectID:   projectID,
		tokenSource: oauth2.ReuseTokenSource(nil, creds.TokenSource),
	}, nil
}

// AccessToken returns a currently-valid GCP access token, refreshing
// transparently via the underlying TokenSource on expiry.
func (v *VertexAuth) AccessToken(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.tokenSource == nil {
		return "", fmt.Errorf("vertex: token source not initialized")
	}
	tok, err := v.tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("vertex token: %w", err)
	}
	return tok.AccessToken, nil
}

// ProjectID returns the project_id parsed from the SA JSON. May be empty for
// non-service-account credential types — callers should fall back to env or
// config values when this is empty.
func (v *VertexAuth) ProjectID() string {
	if v == nil {
		return ""
	}
	return v.projectID
}

// Path returns the resolved path to the credential file (after env-var and
// `~` expansion). Useful for diagnostic logging.
func (v *VertexAuth) Path() string {
	if v == nil {
		return ""
	}
	return v.path
}

// resolveVertexAuthPath expands the credential path. Precedence:
//  1. explicit `path` argument (after `~` and $env expansion)
//  2. $GOOGLE_APPLICATION_CREDENTIALS
//
// Returns an error if neither yields a value.
func resolveVertexAuthPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	}
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("no credential path (set agent.olium.oauth_cred_path, --oauth-cred, or $GOOGLE_APPLICATION_CREDENTIALS)")
	}

	path = os.ExpandEnv(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand vertex auth path: %w", err)
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}
