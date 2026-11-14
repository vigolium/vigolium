package network

import (
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
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
	// activePolicy is the policyKey of the options the live Dialer was built
	// from, recorded at creation and cleared when the last reference goes.
	activePolicy string
)

// ErrDialerPolicyConflict is returned by Init when the shared dialer already
// exists and was built from a DIFFERENT network policy.
//
// The dialer is process-global and built once, from whichever options reached
// Init first. Every later Init silently adopted it. For a deny list that is the
// wrong direction to fail: a second scan configured to refuse a host would reuse
// a dialer that allows it, and nothing would say so. The tripwire fails closed
// instead — the caller learns its policy cannot be honoured rather than running
// under someone else's.
//
// No current behaviour changes: ExcludeTargets, RestrictLocalNetworkAccess,
// SystemResolvers, DialerTimeout and DialerKeepAlive are not assigned anywhere in
// the tree, so every Init today computes the same key. This exists so the first
// code to wire one of them cannot land the silent-inheritance bug with it; the
// real fix (a scan-local dialer) is a larger change.
var ErrDialerPolicyConflict = errors.New(
	"network dialer already initialized with a different network policy; " +
		"concurrent scans cannot use conflicting exclude/resolver settings")

// policyKey renders the options that shape the dialer's network policy into a
// comparable string. Order-insensitive for the deny list — the same exclusions
// listed in a different order are the same policy — and it covers exactly the
// fields NewDialer reads, so a new field must be added here in the same change
// that makes NewDialer read it.
func policyKey(options *types.Options) string {
	if options == nil {
		return ""
	}
	deny := slices.Clone(options.ExcludeTargets)
	slices.Sort(deny)
	return strings.Join(deny, "\x00") +
		"|restrict_local=" + strconv.FormatBool(options.RestrictLocalNetworkAccess) +
		"|system_resolvers=" + strconv.FormatBool(options.SystemResolvers) +
		"|timeout=" + options.DialerTimeout.String() +
		"|keepalive=" + options.DialerKeepAlive.String()
}

// Init creates the global Dialer instance based on user configuration, or
// reuses the existing one, and registers one reference. Every successful Init
// must be paired with exactly one Close.
//
// Reuse requires the SAME network policy: an Init whose policy differs from the
// live dialer's returns ErrDialerPolicyConflict and takes no reference, so the
// caller must not Close. See ErrDialerPolicyConflict.
func Init(options *types.Options) error {
	mu.Lock()
	defer mu.Unlock()

	key := policyKey(options)

	if Dialer != nil {
		if key != activePolicy {
			return ErrDialerPolicyConflict
		}
		refCount++
		return nil
	}

	dialer, err := NewDialer(options)
	if err != nil {
		return err
	}
	Dialer = dialer
	activePolicy = key
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
	opts.BaseResolvers = baseResolvers(options.Resolvers, systemResolverCount(resolvConfPath()), opts.BaseResolvers)

	opts.Deny = append(opts.Deny, expandedDenyList...)

	// WithDialerHistory stays OFF. It is a write-only cache here: fastdialer
	// records every dialed IP into it, and the only reader is its GetDialedIP,
	// which nothing in vigolium calls - the resolved addresses the scan actually
	// reports come from the DNS prefetch stage and land in host_observations.
	//
	// Turning it on is not free. It makes fastdialer open a LevelDB under
	// os.TempDir() (hybrid.DefaultDiskOptions), and that constructor first sweeps
	// the WHOLE temp directory, lstat'ing every entry whose name contains the
	// executable name to expire hmap dirs older than two days. On a workstation
	// with a large /tmp that sweep alone cost ~180ms of every single vigolium
	// invocation, plus a LevelDB open, a disk write per dial, and one more temp
	// directory left behind. If a reader for the history ever appears, re-enable
	// it with an explicit hybrid Path so the sweep stays off.
	opts.WithDialerHistory = false

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
	// Cleared with the dialer, so a later Init with a different policy builds one
	// rather than conflicting with a policy nothing is holding any more.
	activePolicy = ""
	StopActiveMemGuardian()
}

// baseResolvers picks fastdialer's BaseResolvers. fastdialer tries
// the system resolvers (resolv.conf) first and then round-robins BaseResolvers,
// public 1.1.1.1/8.8.8.8 by default — so internal hostnames leaked to public
// DNS. Explicit resolvers always win; with working system resolvers no public
// base is added; with none the public defaults stay so resolution still works.
func baseResolvers(explicit []string, systemCount int, defaults []string) []string {
	if len(explicit) > 0 {
		return explicit
	}
	if systemCount > 0 {
		return nil
	}
	return defaults
}

// resolvConfPath is the resolver file fastdialer reads (RESOLVERS_PATH
// overrides, as it does in fastdialer).
func resolvConfPath() string {
	if p := os.Getenv("RESOLVERS_PATH"); p != "" {
		return os.ExpandEnv(p)
	}
	return fastdialer.ResolverFilePath
}

// systemResolverCount counts the nameserver lines in a resolv.conf; 0 when the
// file is missing or names none.
func systemResolverCount(path string) int {
	if path == "" {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			n++
		}
	}
	return n
}
