package services

import (
	"net/netip"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/types"
	"golang.org/x/time/rate"
)

// Services contains runtime services used across the application.
type Services struct {
	// Options contains CLI configuration
	Options *types.Options

	// HostLimiter limits concurrent requests per hostname
	HostLimiter *hostlimit.HostRateLimiter

	// RateLimiter, when non-nil, caps the GLOBAL outbound request rate (requests
	// per second) across all hosts — distinct from HostLimiter's per-host
	// concurrency. It is on by default: Options.RateLimit carries the documented
	// 100 rps default (scanning_pace.rate_limit) even when --rate-limit is not
	// typed, and only a rate of 0 ("unlimited") leaves it nil. Shared across every
	// Requester built from these Services (and their WithContext clones), so one
	// token bucket governs the whole scan.
	RateLimiter *rate.Limiter

	// HostErrors tracks host failures for circuit breaking
	HostErrors *hosterrors.Cache

	// Egress is the scan's egress gate over RateLimiter, HostLimiter and
	// HostErrors, built once per scan so every sender shares one wire-attempt
	// counter. Read it through EgressGate, which also covers a Services that
	// never set it or that replaced one of the three components.
	Egress *egress.Gate

	// Notifier sends notifications (Telegram, Discord, etc.)
	Notifier *notify.Manager

	// Dialer is the fastdialer instance for DNS resolution
	Dialer *fastdialer.Dialer

	// DedupManager manages deduplication for modules
	DedupManager *dedup.Manager

	// SendScope, when non-nil, is the scope the requester enforces at send
	// time (pkg/http sendGuard): every request it sends and every redirect hop
	// it follows is judged against it before anything leaves, and the
	// in-scope redirect mode (the default) follows a hop only to a host it
	// admits. With no SendScope nothing is judged and in-scope falls back to
	// same-apex. Set it before the requester sends its first request (the
	// runner installs its scope matcher right after building it); it is read,
	// never written, while traffic flows.
	SendScope SendScope
}

// SendScope is the scope as a sender applies it (config.ScopeMatcher
// implements it): RejectHost judges a host name (host rule, origin mode,
// scope.cidr for an IP literal) and RejectAddress the rest of a destination
// (port, explicit path exclusions, scope.cidr.exclude, and the private-address
// and instance-metadata blocks over the addresses the host resolves to). Each
// returns the refusing rule and pattern, "" when admitted.
type SendScope interface {
	RejectHost(host string) (rule, pattern string)
	RejectAddress(host string, port int, path string, addrs []netip.Addr) (rule, pattern string)
}

// SendScopeOf returns s.SendScope, nil-safe.
func (s *Services) SendScopeOf() SendScope {
	if s == nil {
		return nil
	}
	return s.SendScope
}

// EgressGate returns the gate that applies these Services' rate limiter, host
// limiter and breaker.
//
// It is s.Egress when that gate applies exactly those three. When a caller has
// copied the Services and swapped one of them (the probe phase runs on its own
// rate and host limiter), it is a view over the new components that still
// counts into s.Egress's wire-attempt counter. With no Egress set it is a fresh
// gate over the components. Nil-safe: a nil Services yields an ungated gate.
func (s *Services) EgressGate() *egress.Gate {
	if s == nil {
		return egress.New(egress.Config{})
	}
	cfg := egress.Config{Rate: s.RateLimiter, Hosts: s.HostLimiter, Breaker: s.HostErrors}
	if s.Egress == nil {
		return egress.New(cfg)
	}
	if s.Egress.Matches(cfg) {
		return s.Egress
	}
	return s.Egress.With(cfg)
}
