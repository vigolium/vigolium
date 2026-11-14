package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/deparos/waf"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/proxytarget"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
)

const (
	MaxBodyRead = int64(30 * 1024 * 1024) // 30MB
	// responseHeaderTimeoutFloor is the minimum transport ResponseHeaderTimeout.
	// It sits comfortably above the slowest time-based probe (time-blind SQLi
	// sleeps ~6s) so those responses are never aborted at the transport layer, and
	// it never drops below the configured request timeout (see respHeaderTimeout).
	responseHeaderTimeoutFloor = 30 * time.Second

	// TransportProfileSweep is the many-hosts-one-request-each connection
	// profile. See types.Options.TransportProfile for why the two profiles
	// cannot be collapsed into one.
	TransportProfileSweep = "sweep"
)

// Options per-request
type Options struct {
	NoRedirects           bool
	RawRequest            bool
	IgnoreTimeoutTracking bool
	NoClustering          bool
	DisableCompression    bool // skip Accept-Encoding header so Go auto-decompresses
	// RawRequestTarget, when non-empty, is written verbatim as the HTTP
	// request-line target (request-URI) while the TCP/TLS connection still goes
	// to the request's real host. It enables routing-based SSRF / "Cracking the
	// lens" request-line attacks — e.g. connecting to a victim proxy but writing
	// an absolute-form target "http://127.0.0.1:8080/", a userinfo trick
	// "@collab.net/", or a protocol-relative "//collab.net/". Implies
	// RawRequest: it is routed through the rawhttp client. RawBytes, which
	// carries its own request line, takes precedence if both are set.
	RawRequestTarget string
	// RawBytes, when non-empty, is written to the connection verbatim as the
	// ENTIRE request — request line, headers and body — with no framing
	// normalization whatsoever. It exists for attacks whose payload IS the
	// framing, where any rewrite destroys the test: request smuggling (CL.TE /
	// TE.CL / TE.TE) needs Content-Length and Transfer-Encoding to DISAGREE, and
	// needs duplicate or oddly-cased Transfer-Encoding headers to reach the wire.
	//
	// Neither of those can travel any other path. net/http computes framing from
	// req.ContentLength and req.TransferEncoding and ignores the corresponding
	// headers: a manually set "Transfer-Encoding: chunked" is dropped outright and
	// "Content-Length: 4" is overwritten with the real body length. Even rawhttp's
	// normal path re-derives Content-Length (AutomaticContentLength) and carries
	// headers in an http.Header map, which canonicalizes key case and so cannot
	// express "Transfer-Encoding" and "Transfer-encoding" as two distinct headers.
	// Only these verbatim bytes preserve all of it.
	//
	// Implies RawRequest (rawhttp is the only client that can send them) and
	// disables clustering: the cache keys on the parsed request, which by
	// construction no longer describes what goes out.
	//
	// The caller owns correctness — nothing validates or repairs these bytes.
	// They must be a complete HTTP/1.1 message with CRLF line endings.
	RawBytes []byte
	// clusterScope partitions the response cache by the sending requester's
	// credential identity.
	//
	// It is needed because computeClusterKey hashes the RAW request bytes, while
	// the credential surface — customHeaders and the cookie jar — is applied later
	// in doRequest, AFTER the key exists. When credentials arrive via -H or a
	// carried browser session rather than in the captured bytes, an authenticated
	// request and its credential-stripped twin hash identically, and whichever ran
	// first serves the other from cache inside the 500ms TTL. For an
	// authorization-differential module that collision IS the measurement: it
	// reads authenticated == unauthenticated.
	//
	// Unexported and stamped by ExecuteContext — callers construct Options with
	// exported fields only, so it is "" for the primary requester and non-empty
	// only on a credential-stripped view.
	clusterScope string
}

// Requester executes HTTP requests with rate limiting and host error tracking
type Requester struct {
	client           *retryablehttp.Client
	clientNoRedir    *retryablehttp.Client
	rawClient        *rawhttp.Client
	rawClientNoRedir *rawhttp.Client
	services         *services.Services
	customHeaders    map[string]string
	clusterer        *RequestClusterer
	// clusterScope partitions the shared response cache by credential identity.
	// Empty on the primary requester; set on credential-stripped views.
	clusterScope string
	// defaultCtx, when non-nil, is the context the context-less Execute attaches
	// to outgoing requests. Set per scan task via WithContext so cancellation
	// reaches modules that call Execute (not ExecuteContext). nil → Background.
	defaultCtx context.Context
	// abandonFlag, when non-nil and set, marks the owning module call as abandoned:
	// Execute then refuses to start any NEW request. See WithAbandonFlag.
	abandonFlag *atomic.Bool
	// carried holds browser-harvested per-host sessions (cookies + optional
	// pinned User-Agent) carried forward from the spidering phase. It is a
	// pointer to an atomic-published store so WithContext's shallow copy shares
	// one instance. Always non-nil after NewRequester.
	carried *carriedSessionStore
	// blockNotifier fires a one-time-per-host callback when a response is
	// classified as a WAF/CDN block (captcha / bot-detection / challenge page),
	// so the scan can warn the operator that traffic is being filtered. Pointer
	// field so WithContext's shallow copy shares one instance (and never copies
	// its mutex). Always non-nil after NewRequester; inert until SetBlockNotifier
	// installs a sink.
	blockNotifier *blockNotifier
	// respObserver forwards server-error responses (5xx) to an installed sink so a
	// consumer (the executor) can corroborate a leaked database error surfaced by
	// ANY module's probe, not just the module that sent it. Pointer field so
	// WithContext's shallow copy shares one instance. Always non-nil after
	// NewRequester; inert until SetResponseObserver installs a sink.
	respObserver *responseObserver
	// edgePacer pre-arms the host limiter's pacing the first time a host is seen
	// behind a CDN/WAF edge, so the active phase paces from its first request
	// instead of bursting into the edge and arming a rate-based WAF (see
	// maybePaceEdge). Pointer field so WithContext's shallow copy shares one
	// instance (and its once-per-host dedup). Always non-nil after NewRequester.
	edgePacer *edgePacer
	// poolStats accumulates connection-pool telemetry (reuse ratio, TLS handshakes)
	// via httptrace. Pointer field so WithContext copies and anonymous views share
	// one scan-wide instance. Always non-nil after NewRequester.
	poolStats *poolStats
	// sent counts requests that actually reached the network on this requester
	// (and every WithContext clone of it — pointer field, one instance per scan).
	// It is the numerator of the machine event stream's phase.progress: a
	// consumer watching a 15-minute crawl learns it is moving from this slope and
	// nothing else. Incremented on the executeDirectly path only, so a clusterer
	// cache hit — which sends nothing — correctly does not count. Counts wire
	// attempts: a retry and a followed redirect hop each add one.
	sent *atomic.Int64
	// gate admits every wire attempt (rate token, host slot, quarantine). It is
	// the Services' gate (Services.EgressGate), shared by every clone.
	gate *egress.Gate
	// lane is the host-slot lane this requester's traffic uses. LaneNormal for
	// scan traffic; WithLane(egress.LanePriority) for traffic the scan waits on.
	lane egress.Lane
	// retries is how many times a request that failed at the transport level is
	// re-sent (--retries). Retries run in executeDirectly through the gate, not
	// inside retryablehttp, so each one pays a token and none holds the host slot
	// through its backoff.
	retries int
	// retryBackoff overrides egress.DefaultBackoff (tests).
	retryBackoff func(attempt int) time.Duration
	// live is the scan-time owner of the session credentials this requester
	// sends (nil: none, or a session without a check block). A pointer, so
	// WithContext / WithLane / WithAdditionalHeaders views share it, as they
	// share carried. Its headers are applied after customHeaders, every
	// response is fed back to it (Observe), and a request waits (Wait) while
	// it re-logs in. CloneWithoutCredentials drops it: a credential-stripped
	// view must never sample, or trigger a re-login from, its own 401s.
	live *authentication.LiveSession
	// offline, when non-nil, is returned by every Execute before anything is
	// admitted or dialed, and counted in refused. See NewOfflineRequester.
	offline error
	refused *atomic.Int64
}

// WithLiveSession returns a shallow clone that sends live's credentials and
// reports its responses to live (see Requester.live). A nil live returns a
// clone without one.
func (r *Requester) WithLiveSession(live *authentication.LiveSession) *Requester {
	if r == nil {
		return nil
	}
	clone := *r
	clone.live = live
	return &clone
}

// WithSessionCredentials is WithAdditionalHeaders for a live session: a view
// that adds headers AND sends live's current credentials, in its own cookie
// jar and response-cache partition even when headers is empty (every header
// the session owns may have been pinned by an explicit -H). A nil live is
// exactly WithAdditionalHeaders.
func (r *Requester) WithSessionCredentials(headers []string, live *authentication.LiveSession) (*Requester, error) {
	view, err := r.WithAdditionalHeaders(headers)
	if err != nil || live == nil {
		return view, err
	}
	if view == r {
		if view, err = r.cloneSharingTransport(); err != nil {
			return nil, err
		}
		view.clusterScope = primarySessionClusterScope
	}
	view.live = live
	return view, nil
}

// LiveSession is the live session this requester sends, or nil.
func (r *Requester) LiveSession() *authentication.LiveSession {
	if r == nil {
		return nil
	}
	return r.live
}

// edgePacer fingerprints the CDN/WAF edge fronting a host from ordinary (non-block)
// responses and, the first time a host is seen, pre-arms the host limiter's pacing so
// the active phase never bursts into the edge and arms a rate-based WAF. Each host is
// claimed on its first response, so the header fingerprint runs at most once per host
// — a non-edge host never re-runs it for the rest of the scan. The seen set is a
// sync.Map for lock-free reads on the already-claimed hot path (every response to a
// WAF-fronted host). The operator notice is emitted by the limiter's own
// SetPreArmNotifier, fired once per host across every requester that shares the
// limiter, so this only owns the per-requester dedup.
type edgePacer struct {
	seen sync.Map // key: lowercased host → struct{}; present once fingerprinted
}

// claim records key as fingerprinted, returning true only for the caller that first
// claimed it (lock-free via LoadOrStore), so each host is fingerprinted exactly once
// under concurrency.
func (p *edgePacer) claim(key string) bool {
	_, loaded := p.seen.LoadOrStore(key, struct{}{})
	return !loaded
}

// BlockNotice describes a WAF/CDN block observed on scan traffic. It is passed
// to the sink registered via SetBlockNotifier, once per host.
type BlockNotice struct {
	Host    string // host the block was observed on
	WAFType string // detected WAF/CDN vendor (e.g. "cloudflare", "akamai", "generic")
	Status  int    // HTTP status code of the blocking response
}

// blockNotifier detects WAF/CDN block responses on the requester's traffic and
// invokes sink exactly once per host. A single warning per host is enough: it
// tells the operator that host is filtering traffic and the scan against it is
// likely to be throttled or blocked, without one line per blocked request.
type blockNotifier struct {
	sink func(BlockNotice) // installed once at scan setup, before concurrency starts
	mu   sync.Mutex
	seen map[string]struct{} // hosts already warned about (lowercased)
	// counts is every classified block per host (lowercased) → *atomic.Int64,
	// sink or not, so a phase can tell it was blocked (BlockCounts).
	counts sync.Map
}

// report classifies resp and, on the first confirmed block for host, invokes the
// sink. It is the ergonomic wrapper around reportBlock — classify once, then dedup —
// used by tests and any caller that hasn't already classified the response.
func (n *blockNotifier) report(host string, resp *httpUtils.ResponseChain) {
	if n == nil || n.sink == nil || host == "" || resp == nil {
		return
	}
	n.reportBlock(host, classifyWAFBlock(resp), responseChainStatus(resp))
}

// reportBlock invokes the sink exactly once per host for a precomputed WAF/CDN block
// classification (nil = not a block → no-op). It is a no-op without a sink, so the
// per-response cost is a single nil check until SetBlockNotifier is called. A host is
// only marked "seen" once a block is confirmed, so an ordinary application 403 does
// not suppress a later genuine WAF block on the same host. Callers that already
// classified the response (the hot path shares one result with the limiter feedback)
// call this directly; report is the classify-then-dedup convenience wrapper.
func (n *blockNotifier) reportBlock(host string, block *waf.BlockResult, status int) {
	if n == nil || host == "" || block == nil {
		return
	}
	key := strings.ToLower(host)
	c, ok := n.counts.Load(key)
	if !ok {
		c, _ = n.counts.LoadOrStore(key, new(atomic.Int64))
	}
	c.(*atomic.Int64).Add(1)
	if n.sink == nil {
		return
	}

	// Claim the host under lock so concurrent workers on the same host emit exactly
	// one warning; the sink runs outside the lock.
	n.mu.Lock()
	if _, dup := n.seen[key]; dup {
		n.mu.Unlock()
		return
	}
	n.seen[key] = struct{}{}
	n.mu.Unlock()

	n.sink(BlockNotice{
		Host:    host,
		WAFType: block.WAFType,
		Status:  status,
	})
}

// carriedSessionStore holds per-host CarriedSessions. Sessions are written once
// (after spidering, before scanning concurrency starts) and read on every
// outgoing request, so the map is published via an atomic.Pointer: reads on the
// hot path are a single lock-free load, and the common no-spider case (nil map)
// short-circuits without touching a lock. It is a pointer field on Requester so
// WithContext's shallow copy shares one store (and never copies the atomic).
type carriedSessionStore struct {
	m atomic.Pointer[map[string]httpmsg.CarriedSession]
}

func (s *carriedSessionStore) set(sessions map[string]httpmsg.CarriedSession) {
	s.m.Store(&sessions)
}

func (s *carriedSessionStore) load() map[string]httpmsg.CarriedSession {
	if p := s.m.Load(); p != nil {
		return *p
	}
	return nil
}

// SetCarriedSessions installs browser-harvested per-host sessions on the
// requester. Keys are normalized to bare lowercase hostnames; a request is
// matched against them by host so a session only ever reaches the host it was
// harvested from. Cookies are merged into (never over) a request's existing
// Cookie header, and a non-empty UserAgent is pinned — both applied before the
// operator's -H custom headers so an explicit -H Cookie/User-Agent still wins.
// Safe to call once during scan setup; a nil/empty map is a no-op.
func (r *Requester) SetCarriedSessions(sessions map[string]httpmsg.CarriedSession) {
	if r == nil || r.carried == nil || len(sessions) == 0 {
		return
	}
	normalized := make(map[string]httpmsg.CarriedSession, len(sessions))
	for host, sess := range sessions {
		key := httpmsg.NormalizeHost(host)
		if key == "" {
			continue
		}
		normalized[key] = sess
	}
	r.carried.set(normalized)
}

// ObservedResponse is the payload handed to a response observer for a server-error
// response. RequestRaw and Body are the observer's to read synchronously; a sink
// that retains them must copy (the underlying buffers are reused after Execute).
type ObservedResponse struct {
	Host        string
	URL         string
	ContentType string
	Status      int
	RequestRaw  []byte
	Body        []byte
}

// responseObserver forwards 5xx responses to an installed sink. A 5xx is the
// classic surface on which an application leaks a database error in response to a
// malformed probe, so gating on it keeps the per-response cost a single status
// comparison until an error actually occurs.
type responseObserver struct {
	// sink is accessed concurrently: installed/cleared from scan setup/teardown
	// (SetResponseObserver) while request goroutines — including scan goroutines
	// that outlive a per-module timeout — read it in report. Hold it in an
	// atomic.Pointer so those accesses are race-free. responseObserver is only ever
	// held via *responseObserver (shared across WithContext clones), so the atomic
	// is never copied.
	sink atomic.Pointer[func(ObservedResponse)]
}

// report hands a server-error response to the sink. Gated on status >= 500 so the
// common 2xx/3xx/4xx hot path pays only one integer comparison. The Body is the
// already-buffered response body (no extra I/O); the sink runs synchronously on the
// request goroutine, so it must be cheap and must copy anything it retains.
func (o *responseObserver) report(host, urlStr string, reqRaw []byte, resp *httpUtils.ResponseChain, status int) {
	if o == nil || status < 500 || resp == nil {
		return
	}
	sink := o.sink.Load()
	if sink == nil {
		return
	}
	httpResp := resp.Response()
	if httpResp == nil {
		return
	}
	var body []byte
	if b := resp.Body(); b != nil {
		body = b.Bytes()
	}
	if len(body) == 0 {
		return
	}
	(*sink)(ObservedResponse{
		Host:        host,
		URL:         urlStr,
		ContentType: httpResp.Header.Get("Content-Type"),
		Status:      status,
		RequestRaw:  reqRaw,
		Body:        body,
	})
}

// SetResponseObserver installs a sink invoked for every server-error (5xx) response
// on this requester's traffic, so the executor can corroborate a leaked database
// error from ANY module's probe rather than only the module that sent it. The sink
// runs synchronously on the request goroutine — it must be
// cheap and non-blocking, and must copy any request/response bytes it retains. Call
// during scan setup; a nil sink clears the observer. The installed sink is shared by
// every WithContext clone of this requester.
func (r *Requester) SetResponseObserver(sink func(ObservedResponse)) {
	if r == nil || r.respObserver == nil {
		return
	}
	if sink == nil {
		r.respObserver.sink.Store(nil)
		return
	}
	r.respObserver.sink.Store(&sink)
}

// RequestsSent returns how many requests this requester (and every clone
// sharing its counter) has put on the wire. Safe on a nil Requester and from any
// goroutine; the counter is monotonic for the life of the scan.
func (r *Requester) RequestsSent() int64 {
	if r == nil || r.sent == nil {
		return 0
	}
	return r.sent.Load()
}

// BlockCounts returns how many responses per host (lowercased, as the requester
// keys its host feedback) were classified as WAF/CDN blocks so far, across every
// clone sharing this requester's notifier. A snapshot; nil when none.
func (r *Requester) BlockCounts() map[string]int64 {
	if r == nil || r.blockNotifier == nil {
		return nil
	}
	var out map[string]int64
	r.blockNotifier.counts.Range(func(k, v any) bool {
		if out == nil {
			out = make(map[string]int64)
		}
		out[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

// SetBlockNotifier installs a sink invoked once per host the first time a
// response on that host is classified as a WAF/CDN block (captcha, bot-detection,
// or challenge page). It lets the scan warn the operator that traffic is being
// filtered and results against that host may be incomplete. The sink runs on the
// request goroutine, so it must be cheap and non-blocking. Call once during scan
// setup, before scanning concurrency starts; a nil sink is a no-op. The
// installed sink is shared by every WithContext clone of this requester.
func (r *Requester) SetBlockNotifier(sink func(BlockNotice)) {
	if r == nil || r.blockNotifier == nil || sink == nil {
		return
	}
	r.blockNotifier.sink = sink
}

// WithContext returns a shallow copy of the Requester whose context-less Execute
// uses ctx for cancellation. The copy shares the underlying HTTP clients, rate
// limiter, clusterer, and headers — only the default context differs — so it is
// cheap to create per scan task. The executor hands each active-module task a
// context-bound requester so a per-module timeout or scan shutdown aborts the
// module's in-flight requests even when the module calls Execute directly.
// A nil ctx returns the receiver unchanged.
func (r *Requester) WithContext(ctx context.Context) *Requester {
	if ctx == nil {
		return r
	}
	clone := *r
	clone.defaultCtx = ctx
	return &clone
}

// ErrRequestAbandoned is returned by Execute when the calling module has already
// been abandoned by the executor (its per-module timeout fired, or the phase was
// cancelled), so any result it produces will be discarded.
var ErrRequestAbandoned = errors.New("request abandoned: module call already timed out")

// WithAbandonFlag returns a shallow clone whose Execute refuses to START new
// requests once flag is set. Requests already in flight are untouched.
//
// This exists because a per-module timeout does not stop the module. The
// executor's watchdog returns (nil, false) and the caller discards the result,
// but the module's goroutine keeps running — and kept issuing fresh requests
// against the phase-bound requester. On a real scan that was 725+ timed-out
// modules still hammering the target, competing for the same per-host
// concurrency as live work, to produce findings that are thrown away by
// definition.
//
// The signal is separate from WithContext, and only gates request INITIATION,
// for one specific reason: the request clusterer dedups concurrent identical
// requests through a singleflight group, so one in-flight request is shared by
// every module that asked for it. Attaching a per-module deadline to the
// outgoing request would let the first caller's timeout cancel a request other
// modules are legitimately waiting on. Gating initiation instead stops the
// abandoned module's future load without severing anyone's shared socket.
//
// A flag rather than a context: this is only ever read as a boolean — never
// selected on, never attached to a request — and it is set once per module
// dispatch, the hottest fan-out loop in the scan. A context.WithCancel child
// there would allocate a context plus a CancelFunc and take the shared phase
// context's children-map lock twice per call, serializing hundreds of concurrent
// dispatches on one mutex to carry a single bit.
func (r *Requester) WithAbandonFlag(flag *atomic.Bool) *Requester {
	if flag == nil {
		return r
	}
	clone := *r
	clone.abandonFlag = flag
	return &clone
}

// abandoned reports whether the owning module call has been given up on.
func (r *Requester) abandoned() bool {
	return r.abandonFlag != nil && r.abandonFlag.Load()
}

// targetTLSConfig is the TLS stance for traffic aimed at a scan target —
// hardcoded for pentesting (insecure, max compat), with sni as ServerName when
// the operator pinned one.
//
// This permissiveness is SCOPED TO SCANNER/TARGET TRAFFIC: scan targets
// routinely present self-signed, expired, or wrong-host certs, and a scanner
// that refused them would be useless. It deliberately does NOT apply to
// vigolium's own infrastructure calls — OSINT harvesting (pkg/harvester),
// cloud storage, AI providers, tool downloads, webhooks — which verify certs
// using Go's secure defaults. Keep that split: don't copy InsecureSkipVerify
// into non-target/infra HTTP clients.
//
// Every client that talks to a target builds its config here, so the stance is
// stated once rather than mirrored by comment: the scan transport and the
// auxiliary login transport (LoginTransport) are the two callers today.
func targetTLSConfig(sni string) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		Renegotiation:      tls.RenegotiateOnceAsClient,
		MinVersion:         tls.VersionTLS10,
		// Resume sessions across the scan's connections (pool refills,
		// proxied CONNECT tunnels, the login transport) instead of paying a
		// full handshake for each.
		ClientSessionCache: network.TLSSessionCache(),
	}
	if sni != "" {
		cfg.ServerName = sni
	}
	return cfg
}

// applyExplicitProxy installs the resolved proxy on t as an explicit URL rather
// than ProxyFromEnvironment, because Go's environment resolver bypasses the
// proxy for localhost and a localhost target still has to be observable in the
// operator's proxy log. An unparseable URL is warned about and left unset, so a
// typo degrades to a direct connection rather than failing the client's
// construction. client names the caller in that warning.
func applyExplicitProxy(t *http.Transport, cliProxy, client string) {
	proxyURL := getProxyURL(cliProxy)
	if proxyURL == "" {
		return
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		zap.L().Warn("Invalid proxy URL",
			zap.String("url", proxyURL), zap.String("client", client), zap.Error(err))
		return
	}
	t.Proxy = http.ProxyURL(parsed)
}

// targetRoundTripper returns the RoundTripper a target-facing client sends
// through: t itself when it connects directly, else t wrapped in
// proxytarget.Transport. A scan request whose Host header differs from its URL
// (a Host-header-injection probe, a record whose Host lacks the port) would
// otherwise reach an HTTP proxy addressed to the Host header's authority, and
// the proxy would forward it there instead of to the target. A direct
// transport stays a bare *http.Transport, so retryablehttp's inspection of it
// (keep-alive detection) is unchanged.
func targetRoundTripper(t *http.Transport) http.RoundTripper {
	if t == nil || t.Proxy == nil {
		return t
	}
	return proxytarget.Wrap(t)
}

// getProxyURL returns proxy URL from CLI flag or environment variable.
// CLI flag takes precedence over environment variables.
// Uses explicit proxy URL (not ProxyFromEnvironment) to ensure localhost is proxied.
func getProxyURL(cliProxy string) string {
	if cliProxy != "" {
		return cliProxy
	}
	// Check environment variables (uppercase first, then lowercase)
	if p := os.Getenv("HTTP_PROXY"); p != "" {
		return p
	}
	if p := os.Getenv("http_proxy"); p != "" {
		return p
	}
	if p := os.Getenv("HTTPS_PROXY"); p != "" {
		return p
	}
	if p := os.Getenv("https_proxy"); p != "" {
		return p
	}
	return ""
}

// defaultRequestTimeout is the fallback when a caller leaves Options.Timeout
// unset. It matches retryablehttp.DefaultOptionsSpraying's own value, which is
// what such a caller silently received before the timeout was threaded through —
// so "said nothing" keeps behaving exactly as it did, and only an explicit value
// changes anything.
const defaultRequestTimeout = 30 * time.Second

// effectiveRequestTimeout resolves the one timeout used for the standard client,
// the retry wrapper and the raw client. A zero or negative value means "not
// configured" and takes the default rather than becoming an unbounded client:
// http.Client{Timeout: 0} never gives up, which for a scanner is a hang, not a
// generous deadline.
func effectiveRequestTimeout(configured time.Duration) time.Duration {
	if configured <= 0 {
		return defaultRequestTimeout
	}
	return configured
}

// NewRequester creates a new Requester with all HTTP clients initialized
func NewRequester(options *types.Options, services *services.Services) (*Requester, error) {
	dialer := network.CurrentDialer()
	if dialer == nil {
		return nil, errors.New("network.Dialer not initialized")
	}

	timeout := effectiveRequestTimeout(options.Timeout)

	tlsConfig := targetTLSConfig(options.SNI)

	// Size the idle-connection pool to the per-host concurrency cap. A scanner
	// fans out many requests at the same host, so the transport must keep at
	// least MaxPerHost keep-alive connections warm — otherwise every request past
	// MaxIdleConnsPerHost closes its connection on return and the next one pays a
	// fresh TCP+TLS handshake (~50-150ms). The old hardcoded 10 throttled reuse
	// badly: MaxPerHost defaults to types.DefaultMaxPerHost (40), so 30 of every
	// 40 connections churned.
	//
	// Sized from the per-host limiter's CEILING, not MaxPerHost: the limiter can
	// ramp a healthy host above MaxPerHost, and a pool sized to the starting value
	// would recreate the very churn described above at exactly the concurrency the
	// ramp unlocked. Read from the limiter that already resolved it rather than
	// re-deriving it here — two independent derivations drift silently. With no
	// limiter (or one that can't ramp) this is MaxPerHost as before.
	// Floor at the old 10 and cap at 256 so a pathological --max-per-host can't
	// pin an unbounded idle pool of file descriptors.
	peakPerHost := options.MaxPerHost
	if services != nil && services.HostLimiter != nil {
		peakPerHost = max(peakPerHost, services.HostLimiter.CeilingPerHost())
	}
	maxIdlePerHost := min(max(peakPerHost, 10), 256)
	// The global idle pool scales with the per-host cap so multi-host scans keep
	// enough warm connections across hosts. maxIdlePerHost >= 10 guarantees this is
	// always >= the old 100 floor.
	maxIdleConns := maxIdlePerHost * 10

	// ResponseHeaderTimeout is the transport-level cap on waiting for response
	// headers. The old hard-coded 5s aborted deliberately-delayed responses (e.g.
	// time-based blind SQLi probes that sleep ~6s) as transport-level false
	// negatives. Floor it well above any time-based probe (and never below the
	// configured request timeout) so those probes complete; the request/context
	// timeout — not this transport backstop — governs a genuinely stalled server.
	// The floor also guards against a degenerate/misconfigured tiny options.Timeout
	// making the transport reject every response instantly.
	respHeaderTimeout := max(timeout, responseHeaderTimeoutFloor)

	// Sweep profile: many hosts, one request each. Every pooling assumption
	// above inverts here (see types.Options.TransportProfile).
	//
	// Keep-alives go off because the pool can almost never be hit — the next
	// request is to a different host — while each idle socket still holds a file
	// descriptor for IdleConnTimeout. Across thousands of hosts that is the
	// difference between a bounded fd count and "dial: too many open files".
	// Sending Connection: close also makes the SERVER the active closer, so
	// TIME_WAIT accumulates on their side rather than burning through this
	// box's ~28k ephemeral ports.
	//
	// The MaxIdleConns* values computed above are therefore left as they are and
	// simply go unused: DisableKeepAlives makes Go refuse every connection at
	// tryPutIdleConn, so no idle-pool sizing is reachable. Tuning them for this
	// profile would be configuring a pool that cannot be populated. The cost
	// accepted here is that a same-host redirect hop or a retry re-handshakes;
	// that is the trade the fd bound is bought with.
	//
	// The response-header timeout drops to the request timeout with no floor.
	// The floor exists to protect deliberately-delayed responses from
	// time-based probes; a sweep sends no such probe, and the hosts that accept
	// a connection and then say nothing are exactly what makes a large sweep
	// take hours. Here the tail IS the run time.
	sweep := strings.EqualFold(options.TransportProfile, TransportProfileSweep)
	if sweep {
		respHeaderTimeout = timeout
	}

	// Built before the transport so the dial hooks below can close over it: it is
	// the transport's own dialers, not httptrace, that see every real connection
	// (see poolStats.connDialed for why that distinction matters).
	poolStats := newPoolStats()

	// Transport factory
	makeTransport := func() *http.Transport {
		t := &http.Transport{
			// NOTE: ForceAttemptHTTP2 is currently inert. Setting a custom
			// DialTLSContext makes Go skip its own TLS+ALPN handling, so the
			// transport never negotiates h2 and never populates TLSNextProto —
			// regardless of this flag. This is deliberate: the scanner operates over
			// HTTP/1.1 so request smuggling, header-ordering, raw-request, and
			// timing modules keep a 1:1 request↔connection mapping that h2
			// multiplexing would break. To ever enable h2, the custom
			// DialTLSContext below must be removed and ALPN wired via the shared
			// tlsConfig (NextProtos) / http2.ConfigureTransport.
			ForceAttemptHTTP2: options.ForceAttemptHTTP2 && !sweep,
			// Wrapped so every real connection establishment is tallied — httptrace
			// cannot see them reliably (see poolStats.connDialed).
			DialContext:            poolStats.countDials(dialer.Dial),
			DialTLSContext:         poolStats.countDials(network.DialTLSResumable(dialer)),
			TLSClientConfig:        tlsConfig,
			DisableKeepAlives:      sweep,
			MaxIdleConns:           maxIdleConns,
			MaxIdleConnsPerHost:    maxIdlePerHost,
			IdleConnTimeout:        90 * time.Second,
			ResponseHeaderTimeout:  respHeaderTimeout,
			MaxResponseHeaderBytes: 48 * 1024,
			ReadBufferSize:         16 * 1024,
			// Only requests that carry an explicit "Expect: 100-continue" header
			// wait on this; every other request is unaffected. Left at the zero
			// value, Go documents the opposite of what a caller setting that
			// header wants — "no timeout and causes the body to be sent
			// immediately, without waiting for the server to approve" — which
			// silently discards the one benefit of advertising a huge body:
			// letting an edge refuse it off the Content-Length before it is
			// uploaded. The multi-MiB probes (node2shell) are the only senders.
			ExpectContinueTimeout: 1 * time.Second,
		}
		applyExplicitProxy(t, options.ProxyURL, "scanner")
		return t
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, errors.Wrap(err, "could not create cookiejar")
	}

	retryOpts := scanRetryOptions()
	// MUST be carried over from options: NewWithHTTPClient hands these options to
	// retryablehttp.NewClient, which overwrites the supplied http.Client's Timeout
	// with its own whenever retryOpts.Timeout > 0. DefaultOptionsSpraying carries
	// 30s, so leaving it alone silently discarded the Timeout set on both clients
	// below — --timeout was a no-op on this path and every request ran on 30s,
	// double the flag's own 15s default, in both directions (a short timeout was
	// ignored, a long one was truncated). DefaultOptionsSpraying also sets
	// NoAdjustTimeout, so this value is used as-is rather than scaled to 30%.
	retryOpts.Timeout = timeout

	maxRedir := options.MaxRedirects
	if maxRedir == 0 {
		maxRedir = 10
	}

	// Resolved ONCE and shared by the standard client and both raw clients, so
	// "which redirects does this scan follow" has a single answer. The raw path
	// cannot express same-host/same-apex (rawhttp only has a follow/don't bool),
	// so it follows for any mode except off — documented here rather than
	// silently diverging.
	redirectMode := ResolveRedirectMode(options)

	// Single shared transport — connection pooling is a transport-level concern.
	// Redirect policy is a client-level concern configured via CheckRedirect.
	// Sharing the transport means connections are reused across both client variants.
	sharedTransport := targetRoundTripper(makeTransport())

	// One gate for every clone of this requester (see Services.EgressGate), and
	// the attempt counter, both needed by the redirect policy below.
	gate := services.EgressGate()
	sent := &atomic.Int64{}

	// Client with redirects
	client := newScanRetryClient(&http.Client{
		Transport:     sharedTransport,
		Timeout:       timeout,
		Jar:           jar,
		CheckRedirect: gateRedirects(makeRedirectFunc(redirectMode, maxRedir), gate, sent),
	}, retryOpts)

	// Client without redirects
	clientNoRedir := newScanRetryClient(&http.Client{
		Transport:     sharedTransport,
		Timeout:       timeout,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, retryOpts)

	// retryablehttp's HTTP/2 fallback client is built from its own defaults and
	// ignored --proxy; both retry clients share one replacement that does not.
	h2Fallback := newHTTP2FallbackTransport(poolStats.countDials(dialer.Dial), tlsConfig, options.ProxyURL, respHeaderTimeout)
	h2FallbackRT := targetRoundTripper(h2Fallback)
	pinHTTP2Fallback(client, h2FallbackRT)
	pinHTTP2Fallback(clientNoRedir, h2FallbackRT)

	// Raw HTTP clients. rawhttp.DefaultOptions is a shared package-level
	// *Options; copy it by value so per-requester tuning stays local. The old
	// `rawOpts := rawhttp.DefaultOptions` aliased the global pointer, so every
	// field write below mutated the shared default — racing when requesters were
	// constructed concurrently, and leaking the no-redirect tuning back onto the
	// redirect client (both pointed at the same struct).
	rawOpts := *rawhttp.DefaultOptions
	rawOpts.Timeout = timeout
	if proxyURL := getProxyURL(options.ProxyURL); proxyURL != "" {
		rawOpts.Proxy = proxyURL
	} else {
		rawOpts.FastDialer = dialer
	}
	rawOpts.FollowRedirects = redirectMode != RedirectModeOff
	rawOpts.MaxRedirects = maxRedir
	rawClient := rawhttp.NewClient(&rawOpts)

	rawOptsNoRedir := rawOpts
	rawOptsNoRedir.FollowRedirects = false
	rawOptsNoRedir.MaxRedirects = 0
	rawClientNoRedir := rawhttp.NewClient(&rawOptsNoRedir)

	r := &Requester{
		client:           client,
		clientNoRedir:    clientNoRedir,
		rawClient:        rawClient,
		rawClientNoRedir: rawClientNoRedir,
		services:         services,
		customHeaders:    parseHeaders(options.Headers),
		carried:          &carriedSessionStore{},
		blockNotifier:    &blockNotifier{seen: make(map[string]struct{})},
		respObserver:     &responseObserver{},
		edgePacer:        &edgePacer{},
		poolStats:        poolStats,
		sent:             sent,
		gate:             gate,
		retries:          max(options.Retries, 0),
	}

	// Keep the edge-pacer's once-per-host dedup in sync with the limiter's entry
	// lifetime: when an idle host is evicted, drop it from the dedup so a fresh,
	// full-rate entry created later is re-fingerprinted and re-armed rather than
	// pinned at full rate by the stale (monotonic) claim.
	if services != nil && services.HostLimiter != nil {
		ep := r.edgePacer
		// The subscription lives for the limiter's (scan's) lifetime. Anonymous views
		// (CloneWithoutCredentials) share this edgePacer rather than registering their
		// own, so the number of subscriptions stays bounded to the real setup-time
		// requesters (main + per-session).
		services.HostLimiter.AddEvictNotifier(func(host string) {
			ep.seen.Delete(strings.ToLower(host))
		})
	}

	if options.ClusterRequests {
		// Size the dedup LRU to scan concurrency so a wide active-module fan-out
		// doesn't evict still-fresh entries before their TTL elapses.
		r.clusterer = NewRequestClustererWithSize(ClustererSizeForConcurrency(options.Concurrency))
	}

	return r, nil
}

// applyCarriedSession merges the browser-harvested session for the request's
// host into the outgoing request: a pinned User-Agent (only when one was
// carried) and the harvested cookies merged into any existing Cookie header.
// A no-op when no session was harvested or none matches this host.
func (r *Requester) applyCarriedSession(req *retryablehttp.Request) {
	if r.carried == nil {
		return
	}
	// Fast-out before deriving the host key: most scans don't --spider, so the
	// map is nil and this costs a single lock-free load on the request hot path.
	sessions := r.carried.load()
	if len(sessions) == 0 {
		return
	}
	// req.Hostname() is already port-stripped, so the lookup key only needs
	// case-folding to match the NormalizeHost-normalized map keys.
	sess, ok := sessions[strings.ToLower(req.Hostname())]
	if !ok {
		return
	}
	if sess.UserAgent != "" {
		req.Header.Set("User-Agent", sess.UserAgent)
	}
	// Evaluated per request, not attached wholesale: the harvested jar carries
	// Domain/Path/Secure/Expires, so a cookie scoped to /admin, to the exact host,
	// or to https is only sent where a browser would send it. A session harvested
	// without those attributes falls back to its flat header (see CookieHeaderFor),
	// so nothing regresses for an older harvest.
	if carriedCookies := sess.CookieHeaderFor(req.URL.URL, time.Now()); carriedCookies != "" {
		req.Header.Set("Cookie", httpmsg.MergeCookieHeaders(req.Header.Get("Cookie"), carriedCookies))
	}
	// Fill a harvested token-session credential only when the request carries no
	// Authorization of its own — so a replayed authenticated request keeps its own
	// token, and (since this runs before -H) an explicit -H Authorization still wins.
	// Bearer tokens are origin-scoped (scheme+host+port), unlike cookies, so attach
	// the token only when the request's origin matches the one it was harvested from —
	// a token minted for https://host:3000 must never leak to http://host:8080 on the
	// same hostname. An empty Origin (older harvest) falls back to the hostname-only
	// scoping already applied by the map lookup above.
	if sess.AuthorizationHeader != "" && req.Header.Get("Authorization") == "" &&
		(sess.Origin == "" || httpmsg.OriginMatchesURL(sess.Origin, req.URL.URL)) {
		req.Header.Set("Authorization", sess.AuthorizationHeader)
	}
}

// parseHeaders parses header strings in "Name: Value" format.
func parseHeaders(headers []string) map[string]string {
	result := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// CloneWithoutCredentials returns a lightweight anonymous VIEW over the same
// scan-scoped requester: it shares the transport (connection pool), rate limiter,
// response observer, block notifier, edge-pacing dedup, and request clusterer, and
// isolates only the credential surface — a fresh cookie jar and credential-stripped
// headers. Authorization-differential modules must not reuse the primary
// requester's cookie jar/custom auth headers: deleting Authorization from one raw
// request is otherwise undone by doRequest, which reapplies r.customHeaders
// immediately before sending.
//
// Sharing rather than rebuilding (the previous NewRequester clone) matters on a
// large corpus: each old clone minted its own http.Transport + four HTTP clients +
// jar with no idle-connection reclamation, so probe traffic fragmented the pool
// (extra TCP/TLS handshakes) and — because it also got a fresh response observer /
// block state — was invisible to the executor's scan-wide 5xx corroboration and
// edge pacing. The view fixes both: probes reuse the warm pool and stay observed.
// The clusterer is shared, but NOT because the raw-request hash is sufficient on
// its own — it is not; see Options.clusterScope. Isolation comes from the scope
// stamped below, so the shared clusterer only ever coalesces requests that really
// are equivalent.
func (r *Requester) CloneWithoutCredentials() (*Requester, error) {
	view, err := r.cloneSharingTransport()
	if err != nil {
		return nil, err
	}
	view.customHeaders = stripCredentialHeaderMap(r.customHeaders)
	view.live = nil
	// A CONSTANT, not a per-clone id: modules call CloneWithoutCredentials inside
	// ScanPerRequest, i.e. once per record, so a unique-per-clone scope would give
	// every probe its own partition and silently switch clustering off for that
	// whole traffic class. Every view of one requester has the same credential
	// surface (same stripped headers, empty jar), so they are interchangeable and
	// must keep coalescing with each other — only the split from the
	// credential-bearing parent is required, and one clusterer never spans two
	// parents (CloneForScan mints a fresh one per scan).
	view.clusterScope = anonymousClusterScope
	return view, nil
}

// anonymousClusterScope labels the response-cache partition shared by every
// credential-stripped view. The primary requester's scope stays "", so the
// common path adds nothing to the cache key.
const anonymousClusterScope = "anon"

// primarySessionClusterScope labels the response-cache partition used by the
// authenticated view WithAdditionalHeaders returns. Like anonymousClusterScope
// it is a CONSTANT rather than a per-view id: every view built from the same
// session headers has the same credential surface and must keep coalescing with
// its siblings, while staying split from the unauthenticated parent.
const primarySessionClusterScope = "primary-session"

// WithAdditionalHeaders returns a view of r that adds headers to every request.
// It shares r's transport (connection pool), rate limiter, request counter,
// response observer, block notifier, edge pacer and carried sessions, and gets
// its own cookie jar and response-cache partition so authenticated responses
// never coalesce with the anonymous parent's.
//
// It exists for `session.use_in_discovery: false`, which keeps the primary
// session's credentials off the discovery/spidering requester but is documented
// to authenticate the assessment. Adding the headers to the shared requester
// would leak them back into discovery; building a second requester from scratch
// would fragment the connection pool and hide the authenticated traffic from the
// scan-wide 5xx corroboration and edge pacing (see CloneWithoutCredentials).
//
// Carried browser sessions are shared through the same pointer the parent holds,
// so a session installed on the parent AFTER this view is created (spidering
// installs them at the end of its phase, before assessment runs) still applies
// here.
//
// headers are "Name: Value" strings, as on the command line. An added header
// replaces a parent header of the same name case-insensitively, so the session's
// Authorization wins over a stale one inherited from the parent rather than the
// two racing on map iteration order. An empty list returns r unchanged.
func (r *Requester) WithAdditionalHeaders(headers []string) (*Requester, error) {
	if r == nil {
		return nil, errors.New("cannot derive a view of a nil requester")
	}
	added := parseHeaders(headers)
	if len(added) == 0 {
		return r, nil
	}
	view, err := r.cloneSharingTransport()
	if err != nil {
		return nil, err
	}

	addedNames := make(map[string]struct{}, len(added))
	for name := range added {
		addedNames[strings.ToLower(name)] = struct{}{}
	}
	merged := make(map[string]string, len(r.customHeaders)+len(added))
	for name, value := range r.customHeaders {
		// An added header outranks the parent's, so drop the parent entry the
		// added one supersedes instead of leaving both in the map: doRequest
		// Sets every entry and the canonical key would collide.
		if _, overridden := addedNames[strings.ToLower(name)]; overridden {
			continue
		}
		merged[name] = value
	}
	for name, value := range added {
		merged[name] = value
	}
	view.customHeaders = merged
	view.clusterScope = primarySessionClusterScope
	return view, nil
}

// CloneForScan returns a per-scan requester that SHARES the expensive
// transport (connection pool), dialer, and host rate limiter with r, but gives
// the scan its OWN behavioral state that concurrent scans would otherwise
// corrupt on a single shared requester: a fresh cookie jar, a fresh response
// observer (the 5xx corroboration sink — installed per-Execute, so on a shared
// requester the last writer wins and the first to finish clears it for the
// rest), and a fresh request clusterer (keyed on the request hash — sharing it
// would serve one scan's response to another scan's byte-identical request).
//
// The server holds one shared requester and runs multiple lightweight scans
// (scan-url / scan-request) concurrently; this isolates their evidence and
// cookies. The edge-pacer and block-notifier stay shared: they dedup per host
// across the whole process, and giving each scan its own edge-pacer would
// register a new (never-removed) evict subscription on the shared limiter and
// leak subscriptions over the server's lifetime.
func (r *Requester) CloneForScan() (*Requester, error) {
	scoped, err := r.cloneSharingTransport()
	if err != nil {
		return nil, err
	}
	scoped.respObserver = &responseObserver{}
	if r.services.Options.ClusterRequests {
		scoped.clusterer = NewRequestClustererWithSize(ClustererSizeForConcurrency(r.services.Options.Concurrency))
	} else {
		scoped.clusterer = nil
	}
	return scoped, nil
}

// cloneSharingTransport returns a shallow copy of r that SHARES the transport
// (connection pool), dialer, and rate limiter, with a fresh cookie jar on its two
// retry clients so cookies are isolated while pooling is preserved. Callers then
// override only the behavioral state they need to isolate (credential headers,
// response observer, clusterer). Errors if r has no runtime options.
func (r *Requester) cloneSharingTransport() (*Requester, error) {
	if r == nil || r.services == nil || r.services.Options == nil {
		return nil, errors.New("cannot clone requester without runtime options")
	}

	// Fresh cookie jar wrapping the SAME shared transport, so the clone's cookies
	// never mix with the parent jar while connection pooling is preserved.
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, errors.Wrap(err, "could not create cookiejar")
	}

	retryOpts := scanRetryOptions()

	clone := *r
	clone.client = cloneRetryClientWithJar(r.client, jar, retryOpts)
	clone.clientNoRedir = cloneRetryClientWithJar(r.clientNoRedir, jar, retryOpts)
	return &clone, nil
}

// cloneRetryClientWithJar rebuilds a retryablehttp client that shares src's
// transport, timeout, and redirect policy (all carried on the copied *http.Client)
// but swaps in a fresh cookie jar, so an anonymous view keeps connection pooling
// while isolating cookies.
func cloneRetryClientWithJar(src *retryablehttp.Client, jar http.CookieJar, opts retryablehttp.Options) *retryablehttp.Client {
	base := *src.HTTPClient // shares Transport + CheckRedirect, keeps Timeout
	base.Jar = jar
	// NewWithHTTPClient overwrites base.Timeout with opts.Timeout whenever the
	// latter is positive, so carrying it across here is what makes the "keeps
	// Timeout" above true. Done at this single seam rather than at each caller:
	// this is the only function that can drop it, so it cannot be forgotten.
	opts.Timeout = base.Timeout
	clone := newScanRetryClient(&base, opts)
	// NewWithHTTPClient builds a fresh HTTP/2 fallback client from retryablehttp's
	// defaults; carry src's proxy-aware one across instead.
	if src.HTTPClient2 != nil {
		pinHTTP2Fallback(clone, src.HTTPClient2.Transport)
	}
	return clone
}

// stripCredentialHeaderMap returns a copy of the header map with credential-bearing
// entries (per credentialHeaderName) removed.
func stripCredentialHeaderMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for name, value := range in {
		if credentialHeaderName(name) {
			continue
		}
		out[name] = value
	}
	return out
}

func credentialHeaderName(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	switch normalized {
	case "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key",
		"x-api-token", "x-auth-token", "x-access-token", "x-session-token":
		return true
	}
	return strings.Contains(normalized, "credential") ||
		strings.HasSuffix(normalized, "-token") ||
		strings.HasSuffix(normalized, "-api-key") ||
		strings.HasSuffix(normalized, "-session-id")
}

// Execute sends HTTP request with rate limiting, host error tracking,
// and optional request clustering to deduplicate concurrent identical requests.
// It uses the context bound via WithContext (if any) so callers that never touch
// ExecuteContext still honour scan/module cancellation; otherwise it is
// equivalent to the non-cancellable legacy behaviour.
func (r *Requester) Execute(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, time.Duration, error) {
	ctx := r.defaultCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return r.ExecuteContext(ctx, input, opts)
}

// ExecuteContext is the cancellable variant of Execute: ctx is attached to the
// outgoing HTTP request, so cancelling it (scan shutdown or a per-module/active
// timeout) aborts the in-flight request and its retry loop instead of leaving
// the goroutine to drain on its own. A context.Background() ctx is equivalent to
// the legacy non-cancellable Execute.
func (r *Requester) ExecuteContext(ctx context.Context, input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, time.Duration, error) {
	// Refuse new work for a module the executor has already given up on. Checked
	// before the clusterer so an abandoned caller neither starts a request nor
	// joins a singleflight group it would only abandon again.
	if r.abandoned() {
		return nil, 0, ErrRequestAbandoned
	}
	if r.offline != nil {
		r.refused.Add(1)
		return nil, 0, r.offline
	}
	// Verbatim bytes bypass the parsed request entirely, so the cluster key --
	// computed from that request -- no longer describes what goes on the wire.
	// Two probes that differ only in framing would collide and be served each
	// other's cached response, which for a framing attack IS the measurement.
	if len(opts.RawBytes) > 0 {
		opts.RawRequest = true
		opts.NoClustering = true
	}
	// RawRequestTarget is likewise meaningless off the rawhttp path. It used to
	// be documented as "ignored otherwise", which is the same silent-no-op trap
	// that let smuggling probes be re-framed for so long; both existing callers
	// already pass RawRequest, so implying it changes nothing and removes the
	// footgun.
	if opts.RawRequestTarget != "" {
		opts.RawRequest = true
	}
	if r.clusterer != nil && !opts.NoClustering {
		// Stamp this requester's cache partition onto the options copy the
		// clusterer keys on. Callers never set this field.
		opts.clusterScope = r.clusterScope
		return r.clusterer.Execute(input, opts, func(in *httpmsg.HttpRequestResponse, o Options) (*httpUtils.ResponseChain, time.Duration, error) {
			return r.executeDirectly(ctx, in, o)
		})
	}
	return r.executeDirectly(ctx, input, opts)
}

// CloseIdleConnections returns this requester's idle keep-alive connections to
// the OS. Safe to call more than once and on a nil receiver.
//
// Call it from the component that OWNS the requester, once its work has
// drained — never from a WithContext/credential view, which shares the same
// transport and would pull the sockets out from under the owner. It does not
// touch the process-global fastdialer (that is reference-counted by
// network.Init/Close) and does not close the raw clients, whose Close would
// close a fastdialer they may have only borrowed.
//
// Without this, a finished scan left up to MaxIdleConns sockets pinned for
// IdleConnTimeout (90s). One scan recovers on its own; a server process running
// scans back to back, or a host sweep that touched thousands of origins,
// accumulates them.
func (r *Requester) CloseIdleConnections() {
	if r == nil {
		return
	}
	for _, c := range []*retryablehttp.Client{r.client, r.clientNoRedir} {
		if c == nil || c.HTTPClient == nil {
			continue
		}
		// http.Client forwards to its transport, bare or proxytarget-wrapped.
		c.HTTPClient.CloseIdleConnections()
	}
}

// Clusterer returns the request clusterer (nil if clustering is disabled).
func (r *Requester) Clusterer() *RequestClusterer {
	return r.clusterer
}

// executeDirectly sends one logical request through the egress gate, retrying
// transport failures. ctx is propagated to the outgoing request for cancellation.
//
// Each wire attempt is a separate gate admission (egress.Gate.Do): a rate token,
// a host slot, the quarantine check and Admit, then the send, then the slot
// back and the outcome to the breaker. The backoff before a retry is slept
// WITHOUT the slot. Retries used to run inside retryablehttp, which took no
// token for them and held the slot through every 1–10s backoff sleep.
//
// Only the standard client retries. A raw request (framing attacks, request-line
// tricks) is exactly one round trip by design — the response must belong to the
// bytes that were sent — so it never did, and does not now.
func (r *Requester) executeDirectly(ctx context.Context, input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, time.Duration, error) {
	host := ""
	hostPort := ""
	if svc := input.Service(); svc != nil && svc.Host() != "" {
		host = svc.Host()
		hostPort = net.JoinHostPort(host, strconv.Itoa(svc.Port()))
	}

	policy := egress.RetryPolicy{
		Retryable:     retryableTransportError,
		Backoff:       r.retryBackoff,
		IgnoreTimeout: opts.IgnoreTimeoutTracking,
	}
	if !opts.RawRequest {
		policy.MaxRetries = r.retries
	}

	// A session re-login in progress parks the request here, BEFORE the gate:
	// a parked request must not hold the host slot the re-login needs.
	if err := r.live.Wait(ctx); err != nil {
		return nil, 0, err
	}

	var (
		resp    *httpUtils.ResponseChain
		elapsed time.Duration
		creds   *authentication.Credentials
	)
	attempts, err := r.gate.Do(ctx, hostPort, r.lane, policy, func(int) error {
		// The clock starts HERE — after the rate token and the host slot, right
		// before the send. Queue time is vigolium's own saturation, not the
		// target's latency. It covers this attempt only (redirect hops and body
		// capture included): an earlier failed attempt and its backoff say
		// nothing about how fast the host answered the request that succeeded.
		start := time.Now()
		// Counted before the send, not after a successful one: a request that
		// timed out or was refused still hit the network, and a progress counter
		// that only moves on success reads as a stalled scan against a failing
		// host — the exact case a consumer most needs to see moving.
		r.sent.Add(1)
		// Read per attempt, so a retry after a re-login sends the new
		// credentials and its response is attributed to their generation.
		creds = r.live.Credentials()
		var sendErr error
		resp, sendErr = r.doRequest(ctx, input, opts, creds)
		elapsed = time.Since(start)
		if sendErr != nil {
			// Feed transport failures (timeout/reset/refused) to the adaptive
			// limiter so it can back the host off; a no-op in static mode.
			r.reportHostFeedback(host, 0, sendErr, false)
		}
		return sendErr
	})
	if err != nil {
		if attempts > 1 && ctx.Err() == nil {
			// The message retryablehttp used to give a retried failure, so logs
			// and transport-error classification read the same as before.
			err = fmt.Errorf("%s giving up after %d attempts: %w", requestLabel(input), attempts, err)
		}
		return nil, 0, err
	}

	// Classify a WAF/CDN block once (cheap status pre-gate; only reads the body on a
	// block-status response) and feed that single result to both consumers: the
	// adaptive limiter (arms/backs-off WAF-auto-arm throttling) and the once-per-host
	// operator warning. Sharing the result avoids re-running ClassifyParts per block.
	status := responseChainStatus(resp)
	block := classifyWAFBlock(resp)
	r.reportHostFeedback(host, status, nil, block != nil)
	r.blockNotifier.reportBlock(host, block, status)
	// Proactively pace a host the first time it is seen behind a CDN/WAF edge, so a
	// later phase's burst never arms a rate-based WAF. Runs on every phase's traffic
	// through this shared requester (heuristics/discovery hit each host before the
	// active phase), so the pre-arm lands ahead of the active-module fan-out.
	r.maybePaceEdge(host, resp, block != nil)
	// Feed the session's logged-out detector. Status and Location are O(1);
	// the body is only read on the sampled responses (inside Observe).
	if r.live != nil && creds != nil {
		var hdr http.Header
		if hr := resp.Response(); hr != nil {
			hdr = hr.Header
		}
		r.live.Observe(creds.Gen, status, hdr, resp.BodyBytes())
	}
	// Forward server errors to the corroboration observer. Gate on 5xx here (not
	// just inside report) so the URL string is materialized only for server errors,
	// never on the 2xx/3xx/4xx hot path. No-op without an installed sink.
	if status >= 500 && r.respObserver.sink.Load() != nil {
		urlStr := ""
		if u, err := input.URL(); err == nil && u != nil {
			urlStr = u.String()
		}
		r.respObserver.report(host, urlStr, input.Request().Raw(), resp, status)
	}
	return resp, elapsed, nil
}

// requestLabel is "METHOD url" for error messages.
func requestLabel(input *httpmsg.HttpRequestResponse) string {
	method := ""
	if req := input.Request(); req != nil {
		method = req.Method()
	}
	if u, err := input.URL(); err == nil && u != nil {
		return strings.TrimSpace(method + " " + u.String())
	}
	return method
}

// requestBuildError is a request that could not be built from its raw form (an
// unparseable URL, say). Nothing reached the wire and every attempt fails the
// same way, so it is never retried: before retries moved into executeDirectly
// the build ran outside retryablehttp's loop, and retrying it here costs a full
// backoff per malformed probe (path-normalization sends dozens).
type requestBuildError struct{ err error }

func (e *requestBuildError) Error() string { return "failed to build request: " + e.err.Error() }
func (e *requestBuildError) Unwrap() error { return e.err }

// retryableTransportError is the retry decision retryablehttp made before
// retries moved into executeDirectly (CheckRecoverableErrors): any transport
// error (a client timeout included), except on a cancelled ctx, a redirect-limit or bad-scheme error, an
// untrusted certificate, a permanent network error, or a request that could
// not be built (requestBuildError). A gate refusal
// (quarantine, slot timeout) never reaches it: Do stops on those itself.
func retryableTransportError(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	var buildErr *requestBuildError
	if errors.As(err, &buildErr) {
		return false
	}
	// CheckRecoverableErrors type-asserts *url.Error directly, so hand it the
	// url.Error inside whatever wrapping doRequest added.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr
	}
	ok, _ := retryablehttp.CheckRecoverableErrors(ctx, nil, err)
	return ok
}

// scanRetryOptions are the retryablehttp options every scan client uses. Its
// own retry loop is OFF (RetryMax 0): executeDirectly retries through the
// egress gate instead. The returned options still need Timeout set.
func scanRetryOptions() retryablehttp.Options {
	opts := retryablehttp.DefaultOptionsSpraying
	opts.RetryMax = 0
	opts.RetryWaitMax = 10 * time.Second
	return opts
}

// newScanRetryClient wraps hc in a retryablehttp client with opts, and makes a
// failed attempt return its own error rather than retryablehttp's "giving up
// after 1 attempts" wrapper, which with retries off described nothing and hid
// the *url.Error from the retry decision.
//
// It also decides KillIdleConn from the transport underneath. retryablehttp
// derives that switch only when the client's Transport is a bare
// *http.Transport; behind proxytarget.Wrap (every --proxy scan) it kept
// DefaultOptionsSpraying's true and dropped the whole idle pool every 100
// requests, so a proxied scan re-dialed and re-handshook continuously.
func newScanRetryClient(hc *http.Client, opts retryablehttp.Options) *retryablehttp.Client {
	opts.KillIdleConn = killIdleConns(hc.Transport)
	c := retryablehttp.NewWithHTTPClient(hc, opts)
	c.ErrorHandler = retryablehttp.PassthroughErrorHandler
	return c
}

// killIdleConns is retryablehttp's own KillIdleConn rule (a transport that never
// pools gains nothing from keeping idle connections), applied through the
// proxytarget wrapper it cannot see past. An unrecognised RoundTripper keeps its
// pool: periodically closing a pool that is reused is the costly mistake.
func killIdleConns(rt http.RoundTripper) bool {
	t, ok := proxytarget.Base(rt)
	if !ok {
		return false
	}
	return t.DisableKeepAlives || t.MaxConnsPerHost < 0
}

// gateRedirects wraps a redirect policy so every hop it follows takes a rate
// token and counts as a wire attempt. The original request's host slot is held
// through the hops (usually the same host; a cross-host hop holding the first
// host's slot is accepted). A hop the policy refuses costs nothing.
func gateRedirects(policy func(*http.Request, []*http.Request) error, gate *egress.Gate, sent *atomic.Int64) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if err := policy(req, via); err != nil {
			return err
		}
		if err := gate.Token(req.Context()); err != nil {
			return err
		}
		sent.Add(1)
		return nil
	}
}

// WithLane returns a shallow clone whose traffic uses lane's host slots. A
// login, re-login or reachability preflight runs on egress.LanePriority so it
// never queues behind the module requests that are waiting for it.
func (r *Requester) WithLane(lane egress.Lane) *Requester {
	if r == nil || r.lane == lane {
		return r
	}
	clone := *r
	clone.lane = lane
	return &clone
}

// Gate returns the egress gate this requester sends through (nil-safe: a nil
// requester returns a nil gate, which admits everything).
func (r *Requester) Gate() *egress.Gate {
	if r == nil {
		return nil
	}
	return r.gate
}

// AcquireDial admits one connection a module opens itself (a TLS handshake for
// certificate or cipher probing) through the scan's egress gate: a rate token,
// a host slot, the quarantine check, one counted attempt. Call the returned
// release when the connection is closed. The outcome is not reported to the
// breaker: a probe that offers a cipher the server refuses says nothing about
// whether the host is alive.
//
// It waits on the requester's task context (WithContext), so a module timeout
// or scan shutdown unblocks it. Nil-safe: on a nil requester it admits
// immediately.
func (r *Requester) AcquireDial(host string, port int) (func(), error) {
	if r == nil || r.gate == nil {
		return func() {}, nil
	}
	ctx := r.defaultCtx
	if ctx == nil {
		ctx = context.Background()
	}
	release, err := r.gate.AcquireHost(ctx, host, port, r.lane)
	if err != nil {
		return nil, err
	}
	return func() { release(egress.Outcome{Neutral: true}) }, nil
}

// classifyWAFBlock returns the WAF/CDN block classification for resp, or nil if it is
// not a block. It short-circuits on a cheap status pre-gate (waf.IsBlockStatusCode)
// so the common 2xx/3xx hot path never reads the body or runs the classifier; only a
// block-status response pays the ClassifyParts cost. Uses the same accessors as the
// notifier (never FullResponse). This is the single classification both the limiter
// feedback and the operator warning share.
func classifyWAFBlock(resp *httpUtils.ResponseChain) *waf.BlockResult {
	if resp == nil {
		return nil
	}
	httpResp := resp.Response()
	if httpResp == nil || !waf.IsBlockStatusCode(httpResp.StatusCode) {
		return nil
	}
	var body []byte
	if b := resp.Body(); b != nil {
		body = b.Bytes()
	}
	return waf.ClassifyParts(httpResp.StatusCode, httpResp.Header, body)
}

// reportHostFeedback forwards a per-request outcome to the adaptive host limiter.
// No-op without a limiter/host; in static mode Feedback itself is a no-op. It runs
// only on the executeDirectly path, so a clusterer cache hit (no network request)
// correctly produces no feedback. wafBlocked marks a classified WAF/CDN block, which
// arms WAF-auto-arm throttling and always counts as host distress.
func (r *Requester) reportHostFeedback(host string, statusCode int, err error, wafBlocked bool) {
	if host == "" || r.services.HostLimiter == nil {
		return
	}
	r.services.HostLimiter.Feedback(host, statusCode, err, wafBlocked)
}

// maybePaceEdge pre-arms the host limiter's pacing the first time host is seen behind
// a CDN/WAF edge, so a later phase paces that host from its first request instead of
// bursting into the edge and arming a rate-based WAF. It runs at most once per host:
// an edge-fronted host is claimed and short-circuits thereafter; a block response
// (blocked=true) claims the host too — reactive arming (Feedback + blockNotifier)
// already handles it, so we stop re-fingerprinting and fire no pacing notice. Cheap
// on the hot path: a nil/static-mode check, then a map lookup, then a handful of
// header checks only until the host is claimed.
func (r *Requester) maybePaceEdge(host string, resp *httpUtils.ResponseChain, blocked bool) {
	if r.edgePacer == nil || host == "" || resp == nil {
		return
	}
	if r.services.HostLimiter == nil || !r.services.HostLimiter.PreArmable() {
		return
	}
	// Claim the host on its first response (lock-free once claimed): every later
	// response for it short-circuits here, so a non-edge host never re-runs the header
	// fingerprint for the rest of the scan. Edge headers ride every response, so the
	// first one is representative — no need to re-check.
	if !r.edgePacer.claim(strings.ToLower(host)) {
		return
	}
	// A block response is already arming this host reactively (Feedback + the block
	// notifier); the claim above stops us re-fingerprinting, and no pacing notice is due.
	if blocked {
		return
	}
	httpResp := resp.Response()
	if httpResp == nil {
		return
	}
	// The limiter arms the host once and fires the operator notice via its own
	// SetPreArmNotifier, so the notice is emitted exactly once per host even when a
	// different requester (auth prep, a second phase) first tripped the pre-arm.
	if vendor := waf.EdgeFront(httpResp.Header); vendor != "" {
		r.services.HostLimiter.PreArm(host, vendor)
	}
}

// responseChainStatus returns the HTTP status code from a response chain, or 0
// when unavailable.
func responseChainStatus(resp *httpUtils.ResponseChain) int {
	if resp == nil {
		return 0
	}
	if r := resp.Response(); r != nil {
		return r.StatusCode
	}
	return 0
}

// defaultHeaderTemplate is the canonical-keyed form of DefaultBrowserHeaders,
// precomputed once at package init. doRequest merges it into each outgoing
// request via direct map access, avoiding the per-entry strings.EqualFold checks
// and the CanonicalHeaderKey work that http.Header.Get/Set would otherwise pay
// on every request. User-Agent is excluded because its authoritative value is
// resolved per request via DefaultUserAgent() (preset/random/literal override).
// Each value is a single-element slice (cap 1) so any later Header.Add
// reallocates rather than mutating the shared template.
var defaultHeaderTemplate = func() http.Header {
	h := make(http.Header, len(httpmsg.DefaultBrowserHeaders))
	for name, value := range httpmsg.DefaultBrowserHeaders {
		if strings.EqualFold(name, "User-Agent") {
			continue
		}
		h[http.CanonicalHeaderKey(name)] = []string{value}
	}
	return h
}()

func (r *Requester) doRequest(ctx context.Context, input *httpmsg.HttpRequestResponse, opts Options, creds *authentication.Credentials) (*httpUtils.ResponseChain, error) {
	start := time.Now()

	// Attach connection-pool tracing so scan diagnostics can surface reuse ratio /
	// handshake churn (OPT-3). One shared ClientTrace, so this costs a single context
	// wrap. The rawhttp path bypasses net/http, so it is intentionally not traced.
	if r.poolStats != nil && !opts.RawRequest {
		ctx = httptrace.WithClientTrace(ctx, r.poolStats.ct)
		r.poolStats.requests.Add(1)
	}

	req, err := input.BuildRetryableRequestWithContext(ctx)
	if err != nil {
		return nil, &requestBuildError{err: err}
	}

	// Apply default browser headers (only those not already set on the request).
	// Template keys are canonical, so direct map access skips the per-entry
	// canonicalization + EqualFold the old loop ran on every request.
	for canonKey, vals := range defaultHeaderTemplate {
		if opts.DisableCompression && canonKey == "Accept-Encoding" {
			continue
		}
		if existing := req.Header[canonKey]; len(existing) == 0 || existing[0] == "" {
			req.Header[canonKey] = vals
		}
	}
	// User-Agent is resolved via DefaultUserAgent() so a configured global
	// override (http.user_agent) wins over the built-in Chrome string.
	if existing := req.Header["User-Agent"]; len(existing) == 0 || existing[0] == "" {
		req.Header.Set("User-Agent", httpmsg.DefaultUserAgent())
	}

	// Apply a browser-harvested session for this request's host (cookies + an
	// optional pinned User-Agent) so content-discovery and dynamic-assessment
	// inherit the WAF/bot-cleared session the spidering browser established.
	// Applied BEFORE custom headers so an explicit -H Cookie/User-Agent still
	// wins; cookies are merged into (never over) any Cookie already on the
	// request, and the session only applies to the exact host it was harvested
	// from.
	r.applyCarriedSession(req)

	// Apply custom headers (after defaults to allow override)
	for name, value := range r.customHeaders {
		req.Header.Set(name, value)
	}
	// The live session's current credentials win over the copies frozen into
	// customHeaders at setup. They never include a header the operator set
	// explicitly with -H (the LiveSession was built with those names pinned),
	// so an explicit -H still wins.
	if creds != nil {
		for name, value := range creds.Headers {
			req.Header.Set(name, value)
		}
	}

	if r.services.Options.Debug {
		zap.L().Debug("HTTP Request", zap.String("url", req.String()))
		rawReq, err := req.Dump()
		if err == nil {
			zap.L().Debug("HTTP Request Raw", zap.ByteString("raw", rawReq))
		}
	}

	var resp *http.Response
	if opts.RawRequest {
		rawClient := r.rawClient
		if opts.NoRedirects {
			rawClient = r.rawClientNoRedir
		}
		if len(opts.RawBytes) > 0 {
			// Framing-attack path: hand rawhttp the exact bytes and switch off
			// every automatic header it would otherwise synthesize. With
			// CustomRawBytes set rawhttp writes the buffer to the connection and
			// derives nothing, so a deliberately wrong Content-Length and a
			// duplicate/odd-cased Transfer-Encoding both reach the server intact.
			rawOpts := *rawClient.Options
			rawOpts.CustomRawBytes = opts.RawBytes
			rawOpts.AutomaticHostHeader = false
			rawOpts.AutomaticContentLength = false
			// Redirect following would re-issue the request through the normal
			// builder and silently re-frame it; the probe must be exactly one
			// round trip so the response belongs to the bytes we sent.
			rawOpts.FollowRedirects = false
			resp, err = rawClient.DoRawWithOptions(
				req.Method, req.String(), "", req.Header, nil, &rawOpts,
			)
		} else if opts.RawRequestTarget != "" {
			// Routing-based SSRF / request-line attacks ("Cracking the lens"):
			// connect to the real host (req.URL) but emit an attacker-chosen,
			// literal request target on the wire — rawhttp sends the uripath arg
			// verbatim. AutomaticHostHeader is disabled for this call so the
			// request's own Host header (carried in req.Header by
			// BuildRetryableRequest) is sent as-is instead of being overwritten
			// with the connection host; the Host/target mismatch is the whole
			// point of these attacks. The client's options are copied so the
			// shared rawhttp default (used by the smuggling module via Dor) is
			// left untouched.
			rawOpts := *rawClient.Options
			rawOpts.AutomaticHostHeader = false
			// req embeds *urlutil.URL (retryablehttp.Request), so req.String() is the
			// promoted request URL — rawhttp dials its host while RawRequestTarget
			// overrides the on-the-wire request-line target.
			connURL := req.String()
			resp, err = rawClient.DoRawWithOptions(
				req.Method, connURL, opts.RawRequestTarget,
				req.Header, req.Body, &rawOpts,
			)
		} else {
			resp, err = rawClient.Dor(req)
		}
	} else {
		if opts.NoRedirects {
			resp, err = r.clientNoRedir.Do(req)
		} else {
			resp, err = r.client.Do(req)
		}
	}

	if err != nil {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		return nil, err
	}

	if r.services.Options.DumpTraffic {
		dumpTraffic(req.Request, resp, time.Since(start))
	}

	respChain := httpUtils.NewResponseChain(resp, MaxBodyRead)
	// Fill ONCE, at the response the chain starts on — the FINAL response, i.e.
	// the one this request actually ended up at.
	//
	// This used to be a `for respChain.Has() { Fill(); if !Previous() break }`
	// loop, which was a silent and total loss of redirect following. Previous()
	// rewinds the chain in place and Fill() reuses the same two pooled buffers,
	// so the loop did not "fill the whole chain" — it walked to the OLDEST hop
	// and returned the chain sitting there. Every caller of Execute therefore
	// received the first 301 instead of the page behind it: a target that
	// redirects to its real application was recorded as a bodyless 3xx and no
	// module ever saw the application at all. The transport had followed the
	// redirect the whole time; the result was thrown away here.
	//
	// Callers that want the intermediate hops walk them deliberately via
	// RedirectChainHops, which documents that it consumes the chain.
	if err := respChain.Fill(); err != nil {
		// NewResponseChain checks two buffers out of projectdiscovery's
		// global, fixed-size pool (default 10000). On this error path the
		// chain is never handed to the caller, so nothing downstream will
		// Close() it — we must release the buffers here or they leak. Because
		// the pool's getBuffer() acquires with context.Background() (a
		// non-cancellable wait), enough accumulated leaks exhaust the pool and
		// every subsequent request blocks forever, deadlocking the whole scan.
		respChain.Close()
		return nil, errors.Wrap(err, "could not generate response chain")
	}
	return respChain, nil
}

const (
	dumpMaxBody    = 4096
	dumpColorReset = "\033[0m"
	dumpColorCyan  = "\033[36m"
	dumpColorGreen = "\033[32m"
)

// dumpTraffic prints an HTTP request/response pair to stderr in a Burp-style format.
func dumpTraffic(req *http.Request, resp *http.Response, elapsed time.Duration) {
	var reqDump, respDump []byte

	if req != nil {
		reqDump, _ = httputil.DumpRequestOut(req, true)
	}
	if resp != nil {
		respDump, _ = httputil.DumpResponse(resp, true)
	}

	method := ""
	fullURL := ""
	if req != nil {
		method = req.Method
		fullURL = req.URL.String()
	}

	status := ""
	if resp != nil {
		status = resp.Status
	}

	// Truncate response dump if too long
	respBody := string(respDump)
	if len(respDump) > dumpMaxBody {
		respBody = string(respDump[:dumpMaxBody]) + fmt.Sprintf("\n... (%d bytes truncated)", len(respDump)-dumpMaxBody)
	}

	fmt.Fprintf(os.Stderr,
		"\n%s╔══════════════════════════════════════════════════════════════╗%s\n"+
			"%s║ >> %-57s║%s\n"+
			"%s╚══════════════════════════════════════════════════════════════╝%s\n"+
			"%s\n"+
			"%s╔══════════════════════════════════════════════════════════════╗%s\n"+
			"%s║ << %-57s║%s\n"+
			"%s╚══════════════════════════════════════════════════════════════╝%s\n"+
			"%s\n",
		dumpColorCyan, dumpColorReset,
		dumpColorCyan, fmt.Sprintf("%s %s", method, fullURL), dumpColorReset,
		dumpColorCyan, dumpColorReset,
		string(reqDump),
		dumpColorGreen, dumpColorReset,
		dumpColorGreen, fmt.Sprintf("%s  (%.3fs)", status, elapsed.Seconds()), dumpColorReset,
		dumpColorGreen, dumpColorReset,
		respBody,
	)
}
