package agent

import "strings"

// secretEnvNames is the set of env-var names the audit BYOK paths inject
// that must be redacted before they hit logs, runtime.log, or the session
// bundle. Pi providers honor several of these (and the audit harness
// sets the same ones via its own --api-key/--oauth-token flags).
//
// GOOGLE_APPLICATION_CREDENTIALS is included because vigolium does NOT
// inject it today, but operators commonly set it in the inherited shell
// env for vertex providers — and our debug log would echo whatever we
// inject, which means future BYOK additions for vertex creds shouldn't
// have to remember to update the redactor.
//
// Names are sourced from the env-var constants in auth_override.go so
// the producer (PiAuthEnv) and consumer (this redactor) can't drift.
var secretEnvNames = map[string]struct{}{
	envAnthropicAPIKey:      {},
	envClaudeCodeOAuthToken: {},
	envOpenAIAPIKey:         {},
	envOpenAIOAuthCredPath:  {},
	envGoogleAppCredentials: {},
}

// redactedSecretValue is the placeholder substituted for a secret value
// in logs. Distinct from "***" so a reader can grep for the literal
// string when debugging whether redaction fired.
const redactedSecretValue = "<redacted>"

// auditAuthFlagsToRedact is the set of vigolium-audit CLI flags whose value
// is a secret and must be redacted in the printed cmdline. Names match
// AuditDriverAuthFlags.Args() exactly; keep this list in lockstep with that
// renderer.
var auditAuthFlagsToRedact = map[string]struct{}{
	"--api-key":         {},
	"--oauth-token":     {},
	"--oauth-cred-file": {}, // a file PATH, not a key — but it can leak the operator's filesystem layout, so still redacted in logs/streams.
}

// redactEnvSlice returns a copy of envs with the value of any secret
// entry replaced by redactedSecretValue. Non-KEY=VALUE entries (which
// shouldn't happen but cost nothing to handle) pass through unchanged.
//
// O(n) over the slice; called once per audit launch on at most a few
// dozen vars, so the simple linear scan is fine.
func redactEnvSlice(envs []string) []string {
	if len(envs) == 0 {
		return envs
	}
	out := make([]string, len(envs))
	for i, e := range envs {
		idx := strings.IndexByte(e, '=')
		if idx <= 0 {
			out[i] = e
			continue
		}
		name := e[:idx]
		if _, ok := secretEnvNames[name]; ok {
			out[i] = name + "=" + redactedSecretValue
			continue
		}
		out[i] = e
	}
	return out
}

// redactAuditDriverCmdLine takes a rendered command line (e.g. the cmdLine
// builder output in audit_agent.go) and replaces the value following any
// known audit auth flag with redactedSecretValue. Operates on whole
// space-separated tokens so a value containing internal whitespace —
// which the cmdline builder already wraps in single quotes — is still
// redacted as one chunk.
//
// Best-effort, log-only: the live argv handed to the audit subprocess
// is built from cfg.AuditDriverInvocation.Args() and is never affected by
// this transform.
func redactAuditDriverCmdLine(line string) string {
	if line == "" {
		return line
	}
	tokens := strings.Split(line, " ")
	for i := 0; i < len(tokens)-1; i++ {
		if _, ok := auditAuthFlagsToRedact[tokens[i]]; ok {
			tokens[i+1] = redactedSecretValue
		}
	}
	return strings.Join(tokens, " ")
}
