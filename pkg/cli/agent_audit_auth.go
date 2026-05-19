package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent"
)

// resolveAuditAuthOverride builds an agent.AuthOverride from the audit
// CLI's BYOK flags. It applies $ENV / @path indirection (CLI-only),
// resolves which agent (claude/codex) the keys apply to using the same
// precedence as ResolveArchonInvocation (--archon-provider > olium
// provider > claude default), and runs the shared validator before
// returning.
//
// Returns a zero AuthOverride (and no error) when all three flags are
// empty — that's the documented "inherit agent.olium.* config" path.
func resolveAuditAuthOverride(rawAPIKey, rawOAuthToken, rawCredFile, archonProviderOverride, oliumProvider string) (agent.AuthOverride, error) {
	apiKey, err := resolveSecretValue(rawAPIKey, "api-key")
	if err != nil {
		return agent.AuthOverride{}, err
	}
	oauthToken, err := resolveSecretValue(rawOAuthToken, "oauth-token")
	if err != nil {
		return agent.AuthOverride{}, err
	}
	// Cred file is a path, not a literal secret — but we still allow $ENV
	// indirection (and @path for consistency, which just dereferences a
	// file containing another path; rarely useful but cheap to support).
	credFile, err := resolveSecretValue(rawCredFile, "oauth-cred-file")
	if err != nil {
		return agent.AuthOverride{}, err
	}

	override := agent.AuthOverride{
		APIKey:        apiKey,
		OAuthToken:    oauthToken,
		OAuthCredFile: credFile,
		Agent:         agent.ResolveAuthAgent(archonProviderOverride, oliumProvider),
	}
	if err := agent.ValidateAuthOverride(override); err != nil {
		return agent.AuthOverride{}, err
	}
	return override, nil
}

// resolveSecretValue resolves indirection forms accepted by the audit BYOK
// flags (--api-key / --oauth-token / --oauth-cred-file).
//
// Forms (in order tried):
//   - "$NAME"  → os.Getenv("NAME"); errors when unset (so a typo doesn't
//     silently send an empty key to the harness, which would then 401 mid-run)
//   - "@path"  → os.ReadFile(path), trimmed of trailing whitespace; lets a
//     user keep the secret in a file mode-0600 instead of in shell history
//   - anything else: returned as-is (literal)
//
// Empty input returns ""/nil — callers treat that as "no override; inherit
// agent.olium.* config".
//
// CLI-only by design: the REST audit endpoint MUST NOT call this. Resolving
// $ENV from a network-supplied string would let a caller probe the server's
// process env, which is a privilege-escalation primitive.
func resolveSecretValue(raw, flagName string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	switch s[0] {
	case '$':
		name := s[1:]
		if name == "" {
			return "", fmt.Errorf("%s: $ indirection requires a variable name (e.g. --%s '$ANTHROPIC_API_KEY')", flagName, flagName)
		}
		val := os.Getenv(name)
		if val == "" {
			return "", fmt.Errorf("%s: $%s is unset or empty", flagName, name)
		}
		return val, nil
	case '@':
		path := s[1:]
		if path == "" {
			return "", fmt.Errorf("%s: @ indirection requires a path (e.g. --%s @./key.txt)", flagName, flagName)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("%s: read %s: %w", flagName, path, err)
		}
		v := strings.TrimRight(string(data), " \t\r\n")
		if v == "" {
			return "", fmt.Errorf("%s: %s is empty", flagName, path)
		}
		return v, nil
	default:
		return s, nil
	}
}
