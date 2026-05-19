package services

import (
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/types"
)

// Services contains runtime services used across the application.
type Services struct {
	// Options contains CLI configuration
	Options *types.Options

	// HostLimiter limits concurrent requests per hostname
	HostLimiter *hostlimit.HostRateLimiter

	// HostErrors tracks host failures for circuit breaking
	HostErrors *hosterrors.Cache

	// Notifier sends notifications (Telegram, Discord, etc.)
	Notifier *notify.Manager

	// Dialer is the fastdialer instance for DNS resolution
	Dialer *fastdialer.Dialer

	// DedupManager manages deduplication for modules
	DedupManager *dedup.Manager
}
