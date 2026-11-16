package browsercookie

import (
	"context"
	"fmt"
	"runtime"
	"strings"
)

// Check status values.
const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusFail = "fail"
	StatusSkip = "skip"
)

// Check is one diagnostic result.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	// Hint is what the operator should do about it. Present only when there is
	// something to do.
	Hint string `json:"hint,omitempty"`
}

// Diagnosis is the answer to "will reading cookies work on this machine, and if
// not, why".
//
// It exists because every failure mode of a cookie read is indistinguishable
// from an empty result at the call site. An agent that runs this first learns
// whether to bother, and a human learns which approval to grant — rather than
// both concluding the domain simply has no cookies.
type Diagnosis struct {
	OS string `json:"os"`
	// KeyringVia names how the decryption key is fetched on this build, which
	// decides whether an approval granted once keeps working.
	KeyringVia string      `json:"keyring_via"`
	Stores     []StoreInfo `json:"stores"`
	Checks     []Check     `json:"checks"`
	// Ready reports that nothing blocking was found.
	Ready bool `json:"ready"`
}

// KeyringViaDescription explains the consequence of the build's keyring path,
// for the diagnosis output.
func KeyringViaDescription() (via, detail string) {
	if runtime.GOOS != "darwin" {
		if runtime.GOOS == "linux" {
			return "secret-service", "the key comes from the D-Bus Secret Service (GNOME Keyring) or KWallet"
		}
		return "os", "the key comes from the platform's credential store"
	}
	if CGOEnabled {
		return "keychain-api",
			"this build calls the Keychain API directly, so macOS attributes the request to the vigolium binary itself: each read prompts; answer \"Allow\" (this read only) — an \"Always Allow\" grant would let this binary, and anything that runs it, read the browser's key silently"
	}
	return "security(1)",
		"this build shells out to /usr/bin/security, so macOS attributes the request to that Apple-signed binary: each read prompts; answer \"Allow\" (this read only) — an \"Always Allow\" grant would let every process on this machine read the browser's key through security(1) without asking"
}

// Diagnose inspects the machine and reports whether a cookie read can work.
//
// probeKeyring decides whether the OS keyring is actually exercised. Doing so
// is what raises the approval prompt on macOS, so it is opt-in: `doctor` asks
// for it deliberately, because granting the approval is the point of running
// it, while an ordinary read must never prompt for a domain the browser has
// never seen.
func Diagnose(ctx context.Context, q Query, probeKeyring bool) (Diagnosis, error) {
	via, viaDetail := KeyringViaDescription()
	d := Diagnosis{OS: runtime.GOOS, KeyringVia: via, Checks: []Check{}, Stores: []StoreInfo{}}

	stores, err := Discover(ctx, q)
	if err != nil {
		return d, err
	}
	d.Stores = stores

	if len(stores) == 0 {
		d.Checks = append(d.Checks, Check{
			Name:   "stores",
			Status: StatusFail,
			Detail: "no browser cookie store found in the default install locations",
			Hint:   "point --user-data-dir at the profile directory if the browser lives somewhere custom (Chrome for Testing, Chrome Beta, a Playwright profile)",
		})
		return d, nil
	}
	d.Checks = append(d.Checks, Check{
		Name:   "stores",
		Status: StatusOK,
		Detail: fmt.Sprintf("%d store(s): %s", len(stores), strings.Join(storeLabels(stores), ", ")),
	})

	// A cgo build on macOS is not broken, but its keychain grant does not
	// survive a rebuild, which breaks exactly the unattended use this command
	// exists for. Released binaries are built CGO_ENABLED=0 and get the
	// durable path, so this is the local developer build telling on itself.
	keyringPath := Check{Name: "keyring-path", Status: StatusOK, Detail: viaDetail}
	if runtime.GOOS == "darwin" && CGOEnabled {
		keyringPath.Status = StatusWarn
		keyringPath.Hint = "build with CGO_ENABLED=0 (as the released binaries are) for a keychain grant that survives rebuilds"
	}
	d.Checks = append(d.Checks, keyringPath)

	// App-Bound Encryption makes a store unreadable no matter what else is
	// true, so it is reported per store rather than folded into one line.
	for _, s := range stores {
		if !s.AppBound {
			continue
		}
		d.Checks = append(d.Checks, Check{
			Name:   "encryption:" + s.Describe(),
			Status: StatusFail,
			Detail: "App-Bound Encryption (Chrome 127+): the profile key is held by Chrome's elevation service",
			Hint:   "this store cannot be read by another process; drive the browser itself instead",
		})
	}

	for _, s := range stores {
		if !s.WAL {
			continue
		}
		d.Checks = append(d.Checks, Check{
			Name:   "wal:" + s.Describe(),
			Status: StatusWarn,
			Detail: "unflushed writes sit in the store's write-ahead log, which this reader does not consult",
			Hint:   "quit the browser before reading if a cookie set in the last few minutes is missing",
		})
	}

	d.Checks = append(d.Checks, keyringChecks(ctx, stores, probeKeyring)...)

	d.Ready = true
	for _, c := range d.Checks {
		if c.Status == StatusFail {
			d.Ready = false
			break
		}
	}
	return d, nil
}

// keyringChecks reports on access to the decryption keys the Chromium-family
// stores need.
func keyringChecks(ctx context.Context, stores []StoreInfo, probe bool) []Check {
	// One check per distinct keyring item, not per profile: every profile in a
	// user-data directory shares the browser's single key, so probing each
	// would raise the same prompt several times over.
	seen := make(map[string]bool)
	var items []StoreInfo
	for _, s := range stores {
		if !s.NeedsKeyring() || s.SafeStorage == "" || seen[s.SafeStorage] {
			continue
		}
		seen[s.SafeStorage] = true
		items = append(items, s)
	}
	if len(items) == 0 {
		return []Check{{
			Name:   "keyring",
			Status: StatusSkip,
			Detail: "no store needs a keyring secret",
		}}
	}

	var out []Check
	for _, s := range items {
		out = append(out, keyringCheck(ctx, s, probe))
	}
	return out
}

// storeLabels renders each store's short identifier.
func storeLabels(stores []StoreInfo) []string {
	out := make([]string, 0, len(stores))
	for _, s := range stores {
		out = append(out, s.Describe())
	}
	return out
}
