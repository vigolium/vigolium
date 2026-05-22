package network

import (
	"context"
	"sync"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/vigolium/vigolium/pkg/types"
)

// Dialer is a shared fastdialer instance for host DNS resolution. Prefer
// CurrentDialer() for reads; the variable is exported for backward
// compatibility but is mutated under mu.
var Dialer *fastdialer.Dialer

// mu guards Dialer and refCount. Init/Close are reference-counted so that
// overlapping users of the shared dialer — concurrent scans, a server that
// outlives individual scan runners, or sequential tests whose background work
// overlaps — cannot tear the dialer out from under one another. The dialer is
// created on the first Init and destroyed only when the last holder Closes.
var (
	mu       sync.Mutex
	refCount int
)

// Init creates the global Dialer instance based on user configuration, or
// reuses the existing one, and registers one reference. Every successful Init
// must be paired with exactly one Close.
func Init(options *types.Options) error {
	mu.Lock()
	defer mu.Unlock()

	if Dialer != nil {
		refCount++
		return nil
	}

	dialer, err := NewDialer(options)
	if err != nil {
		return err
	}
	Dialer = dialer
	refCount++

	StartActiveMemGuardian(context.Background())

	return nil
}

// CurrentDialer returns the shared dialer (nil if not initialized), read under
// the lock so it doesn't race with Init/Close.
func CurrentDialer() *fastdialer.Dialer {
	mu.Lock()
	defer mu.Unlock()
	return Dialer
}

// NewDialer creates a new fastdialer instance based on user configuration.
func NewDialer(options *types.Options) (*fastdialer.Dialer, error) {
	opts := fastdialer.DefaultOptions
	if options.DialerTimeout > 0 {
		opts.DialerTimeout = options.DialerTimeout
	}
	if options.DialerKeepAlive > 0 {
		opts.DialerKeepAlive = options.DialerKeepAlive
	}

	var expandedDenyList []string
	expandedDenyList = append(expandedDenyList, options.ExcludeTargets...)

	if options.RestrictLocalNetworkAccess {
		expandedDenyList = append(expandedDenyList, networkpolicy.DefaultIPv4DenylistRanges...)
		expandedDenyList = append(expandedDenyList, networkpolicy.DefaultIPv6DenylistRanges...)
	}
	npOptions := &networkpolicy.Options{
		DenyList: expandedDenyList,
	}
	opts.WithNetworkPolicyOptions = npOptions

	if options.SystemResolvers {
		opts.ResolversFile = true
		opts.EnableFallback = true
	}

	opts.Deny = append(opts.Deny, expandedDenyList...)
	opts.WithDialerHistory = true

	dialer, err := fastdialer.NewDialer(opts)
	if err != nil {
		return nil, errors.Wrap(err, "could not create dialer")
	}
	return dialer, nil
}

// Close releases one reference to the global shared fastdialer. The dialer is
// closed and reset to nil only when the final reference is released, allowing a
// later Init() to re-create it. Extra Close() calls (more than Init()) are
// ignored rather than tearing down a dialer still in use.
func Close() {
	mu.Lock()
	defer mu.Unlock()

	if refCount > 0 {
		refCount--
	}
	if refCount > 0 {
		return
	}
	if Dialer != nil {
		Dialer.Close()
		Dialer = nil
	}
	StopActiveMemGuardian()
}
