package network

import (
	"context"

	"github.com/pkg/errors"

	"github.com/vigolium/vigolium/pkg/types"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/networkpolicy"
)

// Dialer is a shared fastdialer instance for host DNS resolution.
// Deprecated: Use NewDialer() to create instances instead of relying on global state.
var Dialer *fastdialer.Dialer

// Init creates the global Dialer instance based on user configuration.
// Deprecated: Use NewDialer() to create instances instead.
func Init(options *types.Options) error {
	if Dialer != nil {
		return nil
	}

	dialer, err := NewDialer(options)
	if err != nil {
		return err
	}
	Dialer = dialer

	StartActiveMemGuardian(context.Background())

	return nil
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

// Close closes the global shared fastdialer.
// Deprecated: Close the dialer instance directly instead.
func Close() {
	if Dialer != nil {
		Dialer.Close()
	}
	StopActiveMemGuardian()
}
