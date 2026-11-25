// Package httpstack builds the standalone HTTP stack a command sends target
// traffic through outside the native-scan Runner: a reference on the shared
// network dialer, a dedup manager, a per-host concurrency limiter, an optional
// global rate limit, and one egress gate over them, behind a Requester.
//
// The direct scan-url / scan-request path, ingest, finding verify, session
// check, kit param-mine and the extension test runner each used to hand-assemble
// this stack, and the copies had drifted: several took a network.Init reference
// they never released. New pairs every piece with Close.
package httpstack

import (
	"fmt"
	"sync"

	"golang.org/x/time/rate"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/types"
)

// Config configures New.
type Config struct {
	// Options are the requester's options and the network policy the shared
	// dialer is initialized with. Required.
	Options *types.Options
	// MaxHosts caps how many hosts the per-host limiter tracks (0 = the
	// limiter's default, 1000). A stack that talks to a handful of hosts
	// passes a small cap.
	MaxHosts int
	// WafPacing paces a host the way a scan does: reactive back-off once it
	// returns WAF/CDN blocks, plus the proactive edge pre-arm unless
	// Options.NoWafPacing.
	WafPacing bool
	// RateLimit caps requests per second across the stack (0 = no global cap;
	// fractions allowed; burst 1).
	RateLimit float64
	// Budget is the request budget the egress gate holds the stack to (nil =
	// none). A refused request fails fast.
	Budget *egress.Budget
	// SendScope is the scope the requester enforces at send time on every
	// request and redirect hop (nil = none; services.Services.SendScope).
	SendScope services.SendScope
}

// Stack is a Requester and the Services behind it. Close releases them.
type Stack struct {
	Requester *http.Requester
	Services  *services.Services

	closeOnce sync.Once
}

// HostLimiterConfig is the per-host limiter config a stack runs with: at most
// maxPerHost concurrent requests per host (0 = the limiter's default), up to
// maxHosts tracked hosts (0 = default), and, under wafPacing, the scan's WAF
// pacing (reactive back-off, plus proactive pre-arm unless noWafPacing).
// Eviction uses the limiter's defaults. The Runner builds its own limiter from
// this too, adding adaptive pacing.
func HostLimiterConfig(maxPerHost, maxHosts int, wafPacing, noWafPacing bool) hostlimit.HostRateLimiterConfig {
	cfg := hostlimit.HostRateLimiterConfig{MaxPerHost: maxPerHost, MaxEntries: maxHosts}
	if wafPacing {
		// Throttle a host only once it starts returning WAF/CDN blocks; a
		// non-WAF scan is unaffected. --no-waf-pacing turns off only the
		// proactive edge pre-arm; reactive back-off stays on.
		cfg.WafAutoArm = true
		cfg.DisablePreArm = noWafPacing
	}
	return cfg
}

// New builds the stack. It takes a reference on the process network dialer
// (network.Init) that Close returns; on error nothing is left held.
func New(cfg Config) (*Stack, error) {
	opts := cfg.Options
	if err := network.Init(opts); err != nil {
		return nil, fmt.Errorf("failed to initialize network: %w", err)
	}
	hostLimiter := hostlimit.NewHostRateLimiter(HostLimiterConfig(opts.MaxPerHost, cfg.MaxHosts, cfg.WafPacing, opts.NoWafPacing))
	svc := &services.Services{Options: opts, DedupManager: dedup.NewManager(), HostLimiter: hostLimiter, SendScope: cfg.SendScope}
	if cfg.RateLimit > 0 {
		svc.RateLimiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), 1)
	}
	// Set before NewRequester, which binds the gate it finds on svc.
	svc.Egress = egress.New(egress.Config{Rate: svc.RateLimiter, Hosts: hostLimiter, Breaker: svc.HostErrors}).
		WithBudget(cfg.Budget)
	s := &Stack{Services: svc}
	requester, err := http.NewRequester(opts, svc)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("failed to create HTTP requester: %w", err)
	}
	s.Requester = requester
	return s, nil
}

// Close releases the dedup manager, the host limiter and the network
// reference. Nil-safe and idempotent.
func (s *Stack) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.Services.DedupManager.Close()
		_ = s.Services.HostLimiter.Close()
		network.Close()
	})
}
