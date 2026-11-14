package oast

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	interactshclient "github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
	"go.uber.org/zap"
)

// Registration and lifecycle of the interactsh-backed Service.
//
// Registration used to run inside New, blocking scan setup for as long as the
// interactsh server took to answer (and, with the library defaults, retrying
// for tens of seconds against a dead server). It now runs in a goroutine: New
// returns at once in the "registering" state, and the caller decides how long
// it is worth waiting with WaitReady. The runner starts it while building the
// scan's infrastructure, so the discovery and spidering phases hide the latency.

// registrationTimeout bounds one registration request, and there is no retry:
// a server that cannot answer within it is reported unavailable instead of
// holding the scan. A var so tests can shorten it.
var registrationTimeout = 3 * time.Second

// pollTimeout bounds each poll/deregister request once registered. Polls are
// periodic and a missed one is retried on the next tick, but a poll can carry a
// batch of interactions, so it gets more room than the registration handshake.
const pollTimeout = 10 * time.Second

// newInteractshClient is the registration seam; tests replace it to simulate a
// slow or failing server without the network.
var newInteractshClient = interactshclient.New

// ErrNotReady is wrapped by WaitReady's error when registration had not finished
// within the wait.
var ErrNotReady = errors.New("registration did not finish in time")

// ErrClosed is wrapped by WaitReady's error when the service was closed before
// registration finished.
var ErrClosed = errors.New("service closed")

// UnavailableError says why OAST is unavailable. Error() is the short form
// used in the one-line operator notice: "<server>: <reason>".
type UnavailableError struct {
	Server string
	Reason string
	Err    error
}

func (e *UnavailableError) Error() string {
	if e.Server == "" {
		return e.Reason
	}
	return e.Server + ": " + e.Reason
}

func (e *UnavailableError) Unwrap() error { return e.Err }

// New creates an OAST service. It returns (nil, nil) only when OAST is disabled
// (nil cfg or enabled: false); the error is always nil and is kept for API
// stability.
//
// In fixed-URL mode (oast_url set) the service is ready immediately; an
// oast_url carrying {nonce} mints a nonce per probe and persists its context to
// oast_payloads (see fixed.go). Otherwise
// registration with the interactsh server starts in the background and New
// returns without waiting: until registration succeeds Enabled() is false and
// GenerateURL returns "". Polling starts automatically once registered. Use
// WaitReady to wait a bounded time for the outcome (a failure included).
// Close stops polling (or abandons an unfinished registration)
// and deregisters.
//
// resolveRequestUUID is an optional function that maps a request hash to a database
// record UUID, enabling Finding records to be linked to their originating HTTP records.
func New(cfg *config.OASTConfig, emitResult func(*output.ResultEvent), repo *database.Repository, scanUUID string, projectUUID string, resolveRequestUUID func(string) string) (*Service, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	// Fixed URL mode: skip interactsh client entirely
	if cfg.OastURL != "" {
		ready := make(chan struct{})
		close(ready)
		return &Service{
			ready:              ready,
			fixedURL:           cfg.OastURL,
			template:           parseFixedTemplate(cfg.OastURL),
			emitResult:         emitResult,
			resolveRequestUUID: resolveRequestUUID,
			repo:               repo,
			scanUUID:           scanUUID,
			projectUUID:        projectUUID,
			blindXSSSrc:        cfg.BlindXSSSrc,
			enabledBlindXSS:    cfg.EnabledBlindXSS,
		}, nil
	}

	serverURL := cfg.ServerURL
	if serverURL == "" {
		serverURL = config.DefaultOASTServer
	}

	pollInterval := time.Duration(cfg.PollInterval) * time.Second
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	gracePeriod := time.Duration(cfg.GracePeriod) * time.Second
	if gracePeriod <= 0 {
		gracePeriod = 10 * time.Second
	}

	s := &Service{
		ready:              make(chan struct{}),
		serverURL:          serverURL,
		fallbackToDefault:  cfg.FallbackToDefault,
		emitResult:         emitResult,
		resolveRequestUUID: resolveRequestUUID,
		repo:               repo,
		scanUUID:           scanUUID,
		projectUUID:        projectUUID,
		pollInterval:       pollInterval,
		gracePeriod:        gracePeriod,
		blindXSSSrc:        cfg.BlindXSSSrc,
		enabledBlindXSS:    cfg.EnabledBlindXSS,
		keepSession:        cfg.KeepSession && repo != nil,
	}
	// The seams are read here, on the caller's goroutine, so a test that swaps
	// them never races a registration goroutine still running from an earlier
	// test.
	go s.register(cfg.Token, newInteractshClient, registrationTimeout)
	return s, nil
}

// register performs the interactsh registration and publishes the client, or
// records why it failed. It always closes s.ready.
func (s *Service) register(token string, newClient func(*interactshclient.Options) (*interactshclient.Client, error), timeout time.Duration) {
	// `timeout` bounds the WHOLE registration, fallback included - the caller
	// waits that long and no longer, so a second attempt has to come out of the
	// same budget rather than doubling it. In the slowest failure mode (a host
	// that drops packets) the first attempt spends it all and there is nothing
	// left to retry with, which is correct: the caller has already given up.
	deadline := time.Now().Add(timeout)

	// One attempt per server, bounded: retries belong to the next scan, not to
	// this one's setup. KillIdleConn so an abandoned attempt leaves no pooled
	// socket.
	httpOpts := retryablehttp.DefaultOptionsSpraying
	httpOpts.Timeout = timeout
	httpOpts.RetryMax = 0
	httpOpts.NoAdjustTimeout = true
	httpOpts.KillIdleConn = true
	httpClient := retryablehttp.NewClient(httpOpts)

	opts := registrationOptions(s.serverURL, token, httpClient)

	client, err := newClient(opts)
	if err != nil {
		if client = s.registerOnFallback(opts, newClient, err, deadline); client == nil {
			return // registerOnFallback recorded the reason and closed ready
		}
	}

	// The registration client is also the polling client. Give polls their own
	// bound now that the handshake is done; nothing else holds it yet.
	if httpClient != nil {
		if httpClient.HTTPClient != nil {
			httpClient.HTTPClient.Timeout = pollTimeout
		}
		if httpClient.HTTPClient2 != nil {
			httpClient.HTTPClient2.Timeout = pollTimeout
		}
	}

	s.lifeMu.Lock()
	if s.closed {
		s.lifeMu.Unlock()
		// Closed while registering: nobody will poll, so deregister right away.
		closeClient(client)
		s.regErr.Store(&UnavailableError{Server: s.ServerURL(), Reason: "closed before registration finished", Err: ErrClosed})
		close(s.ready)
		return
	}
	if err := client.StartPolling(s.pollInterval, s.handleInteraction); err != nil {
		s.lifeMu.Unlock()
		closeClient(client)
		s.fail(&UnavailableError{Server: s.ServerURL(), Reason: "could not start polling: " + err.Error(), Err: err})
		return
	}
	s.client.Store(client)
	s.lifeMu.Unlock()
	close(s.ready)

	zap.L().Info("OAST: registered, polling started",
		zap.String("server", s.ServerURL()),
		zap.Duration("interval", s.pollInterval),
		zap.Duration("grace_period", s.gracePeriod))
}

// registrationOptions is the one place a registration's client options are
// built, so the cleartext rule below holds for the fallback attempt by
// construction rather than by a second evaluation of it.
//
// interactsh retries a failed https registration over cleartext http by
// default, which sends the registration (correlation id, secret key, token) in
// the clear to whatever answered on port 80. Only an operator who wrote
// http:// asked for cleartext.
func registrationOptions(server, token string, httpClient *retryablehttp.Client) *interactshclient.Options {
	return &interactshclient.Options{
		ServerURL:           server,
		Token:               token,
		HTTPClient:          httpClient,
		DisableHTTPFallback: !explicitCleartextServer(server),
	}
}

// registerOnFallback is the second and last registration attempt, against
// config.DefaultOASTServer, after the configured server did not answer. It
// returns nil when the caller must stop, having recorded the reason and closed
// ready; the error it records names BOTH servers, so the notice cannot read as
// though only one thing was tried.
//
// A dial, not unconditional, because a callback carries whatever the payload
// pulled out of the target: on an engagement whose authorization names the
// collector, a public server is egress nobody approved. The token does not
// travel either — it authenticates the operator to the server they named. See
// config.OASTConfig.FallbackToDefault for the operator-facing account.
func (s *Service) registerOnFallback(
	opts *interactshclient.Options,
	newClient func(*interactshclient.Options) (*interactshclient.Client, error),
	cause error,
	deadline time.Time,
) *interactshclient.Client {
	first := &UnavailableError{Server: s.serverURL, Reason: briefRegistrationError(cause), Err: cause}
	// A budget the first attempt already spent is the common case for a host
	// that drops packets, and the caller has stopped waiting by then. Closed is
	// the same answer for a different reason: nobody is left to poll.
	remaining := time.Until(deadline)
	if !s.fallbackToDefault || s.serverURL == config.DefaultOASTServer ||
		remaining <= 0 || s.isClosed() {
		s.fail(first)
		return nil
	}

	zap.L().Warn("OAST: configured server did not answer, falling back to the default",
		zap.String("configured", s.serverURL),
		zap.String("fallback", config.DefaultOASTServer),
		zap.String("reason", first.Reason),
		zap.Duration("budget_left", remaining),
		zap.Bool("token_carried", false))

	// The remaining budget, not a fresh one: `timeout` bounds the whole
	// registration. Both clients, since either may serve the attempt.
	if hc := opts.HTTPClient; hc != nil {
		if hc.HTTPClient != nil {
			hc.HTTPClient.Timeout = remaining
		}
		if hc.HTTPClient2 != nil {
			hc.HTTPClient2.Timeout = remaining
		}
	}

	client, err := newClient(registrationOptions(config.DefaultOASTServer, "", opts.HTTPClient))
	if err != nil {
		s.fail(&UnavailableError{
			Server: s.serverURL,
			Reason: fmt.Sprintf("%s; fallback %s: %s",
				first.Reason, config.DefaultOASTServer, briefRegistrationError(err)),
			Err: err,
		})
		return nil
	}

	s.onFallback.Store(true)
	return client
}

// fail records a registration failure and closes ready. The operator-facing
// notice is the caller's job (the runner prints one line at dynamic-assessment
// start), so this logs at Debug.
func (s *Service) fail(uerr *UnavailableError) {
	s.regErr.Store(uerr)
	zap.L().Debug("OAST: interactsh registration failed",
		zap.String("server", uerr.Server),
		zap.String("reason", uerr.Reason),
		zap.Error(uerr.Err))

	s.lifeMu.Lock()
	close(s.ready)
	s.lifeMu.Unlock()
}

// WaitReady waits up to maxWait (or until ctx is done) for registration to finish.
// It returns nil when the service can mint callback URLs, and an
// *UnavailableError otherwise: the registration failure, ErrNotReady when it was
// still running at the deadline, or ErrClosed. A nil Service reports OAST as
// disabled.
func (s *Service) WaitReady(ctx context.Context, maxWait time.Duration) error {
	if s == nil {
		return &UnavailableError{Reason: "disabled"}
	}
	if s.fixedURL != "" {
		return nil
	}
	if s.ready == nil {
		// Zero-value Service (tests): never registered.
		return &UnavailableError{Server: s.ServerURL(), Reason: "not registered", Err: ErrNotReady}
	}

	select {
	case <-s.ready:
		return s.readyErr()
	default:
	}

	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	select {
	case <-s.ready:
		return s.readyErr()
	case <-timer.C:
		return &UnavailableError{Server: s.ServerURL(), Reason: fmt.Sprintf("registration did not finish within %s", maxWait), Err: ErrNotReady}
	case <-ctx.Done():
		return &UnavailableError{Server: s.ServerURL(), Reason: "wait cancelled: " + ctx.Err().Error(), Err: ctx.Err()}
	}
}

func (s *Service) readyErr() error {
	if uerr := s.regErr.Load(); uerr != nil {
		return uerr
	}
	if s.client.Load() == nil {
		return &UnavailableError{Server: s.ServerURL(), Reason: "closed", Err: ErrClosed}
	}
	return nil
}

// Enabled reports whether the service can mint callback URLs right now: a
// fixed URL is configured, or interactsh registration has succeeded. It is
// false while registration is still running, so callers must not cache it from
// before WaitReady.
func (s *Service) Enabled() bool {
	return s != nil && (s.fixedURL != "" || s.client.Load() != nil)
}

// Flush waits out the grace period so callbacks for payloads planted at the end
// of a round still arrive while polling runs. It returns at once when no
// callback URL was minted since the previous Flush: nothing planted, nothing to
// wait for.
//
// It also writes the payload contexts a {nonce} template minted to
// oast_payloads.
func (s *Service) Flush() {
	if s == nil {
		return
	}
	s.flushPayloads()
	if s.client.Load() == nil {
		return
	}
	if s.minted.Swap(0) == 0 {
		zap.L().Debug("OAST: no callback URL minted, skipping grace period")
		return
	}

	zap.L().Info("OAST: grace period started, waiting for late callbacks",
		zap.Duration("grace_period", s.gracePeriod))
	time.Sleep(s.gracePeriod)
}

// Close stops polling and deregisters from the interactsh server. Safe to call
// more than once and while registration is still running; a registration that
// completes afterwards deregisters itself.
func (s *Service) Close() {
	if s == nil {
		return
	}
	s.flushPayloads()
	s.lifeMu.Lock()
	if s.closed {
		s.lifeMu.Unlock()
		return
	}
	s.closed = true
	client := s.client.Load()
	s.lifeMu.Unlock()

	if client != nil {
		if s.keepSession && s.repo != nil {
			s.keepSessionOpen(client)
			return
		}
		closeClient(client)
	}
}

// closeClient stops polling (interactsh refuses to Close a polling client) and
// deregisters.
func closeClient(c *interactshclient.Client) {
	if c.State.Load() == interactshclient.Polling {
		if err := c.StopPolling(); err != nil {
			zap.L().Debug("OAST: error stopping polling", zap.Error(err))
		}
	}
	if err := c.Close(); err != nil {
		zap.L().Debug("OAST: error closing client", zap.Error(err))
	}
}

// briefRegistrationError condenses interactsh's nested registration error into
// the short reason shown to the operator ("dial timeout", "connection refused").
// The full error stays on UnavailableError.Err and in the debug log.
func briefRegistrationError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "invalid token"):
		return "invalid token"
	case strings.Contains(msg, "client.timeout") || strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "timeout"):
		return "dial timeout"
	case strings.Contains(msg, "connection refused"):
		return "connection refused"
	case strings.Contains(msg, "no such host"):
		return "dns lookup failed"
	case strings.Contains(msg, "network is unreachable") || strings.Contains(msg, "no route to host"):
		return "network unreachable"
	case strings.Contains(msg, "tls") || strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "server gave http response to https client"):
		return "tls handshake failed"
	case strings.Contains(msg, "connection reset") || strings.Contains(msg, "eof"):
		return "connection closed by server"
	}
	short := strings.Join(strings.Fields(err.Error()), " ")
	if len(short) > 160 {
		short = textutil.TruncateUTF8(short, 160) + "…"
	}
	return short
}
