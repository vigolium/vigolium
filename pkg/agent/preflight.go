package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/olium"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// ProviderSetupHint is the one sentence every "no usable provider" message
// ends with, so the README, `agent --list-agents` and the preflight error say
// the same thing about where the provider comes from (decision D25).
const ProviderSetupHint = "the provider is auto-detected unless agent.olium.provider is set; set it with `vigolium config set agent.olium.provider <name>` (list: `vigolium agent --list-agents`)"

// PreflightError is a failed agent preflight. Code is provider_missing when no
// provider could be built from the configuration (unknown name, missing
// credentials), preflight_failed when one was built but its ping failed or
// timed out. It implements Code() so the CLI's error envelope reports the
// condition without matching on message text.
type PreflightError struct {
	code apicontract.ErrorCode
	err  error
}

func (e *PreflightError) Error() string               { return e.err.Error() }
func (e *PreflightError) Unwrap() error               { return e.err }
func (e *PreflightError) Code() apicontract.ErrorCode { return e.code }

// NewProviderMissingError wraps a provider-resolution failure (olium.ResolveProvider
// at a call site that builds its own provider) as provider_missing.
func NewProviderMissingError(err error) error {
	return &PreflightError{code: apicontract.CodeProviderMissing,
		err: fmt.Errorf("no usable AI provider: %w (%s)", err, ProviderSetupHint)}
}

// Preflight verifies that the olium provider can be built AND that its
// credentials work, by issuing a one-token ping. Call it before a multi-phase
// pipeline so a credential or network problem fails in seconds instead of
// after a minute of normalize + discovery work.
//
// The ping is bounded by the caller's ctx (so Ctrl-C stops it) and by
// agent.olium.preflight_timeout (EffectivePreflightTimeout: 15s, 60s for a
// local endpoint). Failures are *PreflightError values: provider_missing when
// no provider could be built, preflight_failed when the ping failed.
func (e *Engine) Preflight(ctx context.Context) error {
	if e.settings == nil {
		return &PreflightError{code: apicontract.CodeProviderMissing, err: fmt.Errorf("agent settings are nil")}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := e.settings.Agent.Olium
	providerName := olium.CanonicalProviderName(cfg.Provider)
	if providerName == "" {
		providerName = "auto-detect"
	}

	sess, err := e.rt().NewSession(&cfg, "")
	if err != nil {
		return &PreflightError{code: apicontract.CodeProviderMissing,
			err: fmt.Errorf("agent preflight: no usable AI provider (%s): %w — %s", providerName, err, ProviderSetupHint)}
	}
	defer func() { _ = sess.Close() }()

	timeout := cfg.EffectivePreflightTimeout()
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, err := e.rt().RunOnSession(pingCtx, &cfg, sess, "Reply with the single word OK.", nil, nil, false)
	if err != nil {
		if errors.Is(pingCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return &PreflightError{code: apicontract.CodePreflightFailed,
				err: fmt.Errorf("agent preflight: provider %q (model=%q) did not answer within %s — raise --preflight-timeout or agent.olium.preflight_timeout, or skip the check with --no-preflight",
					providerName, cfg.Model, timeout.Round(time.Millisecond))}
		}
		code := apicontract.CodePreflightFailed
		if stream.IsDialErr(err) {
			code = apicontract.CodeProviderUnreachable
		}
		return &PreflightError{code: code,
			err: fmt.Errorf("agent preflight: provider %q (model=%q) failed: %w", providerName, cfg.Model, err)}
	}
	if strings.TrimSpace(out.Text) == "" {
		return &PreflightError{code: apicontract.CodePreflightFailed,
			err: fmt.Errorf("agent preflight: provider %q returned no tokens for the ping (likely a silent auth failure)", providerName)}
	}
	return nil
}
