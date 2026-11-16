// Package browsercookie reads cookies out of the local user's own browser
// profiles so an operator — or a coding agent driving one — can hand a live
// session to Playwright, curl, or vigolium's authenticated scan phases without
// copying values out of devtools by hand.
//
// It is a read-only view of stores that already exist on this machine, for the
// user running the process. Nothing here reaches another user's home directory,
// another machine, or the network.
//
// Three things about the underlying stores shape this API, and every one of
// them is a way the naive version of this package lies to its caller:
//
//   - A cookie store is encrypted with a key held by the OS keyring. When that
//     key cannot be read — the user denied the prompt, there is no desktop
//     session — the decrypt fails per row and the rows are skipped. "Access
//     denied" therefore looks exactly like "this domain has no cookies" unless
//     the read errors are captured, which is what [Result.Problem] is for.
//   - Chrome 127+ on Windows wraps the key in App-Bound Encryption, which only
//     Chrome's own elevation service can unwrap. Those stores are unreadable by
//     design and are reported as such rather than returned empty.
//   - Chrome keeps recent writes in a WAL sidecar that the reader does not
//     consult, so a cookie set moments ago may legitimately be missing.
//
// Cookie values are credentials. This package never logs them; callers are
// expected to be equally careful about where they put them.
package browsercookie

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/browserutils/kooky"

	// Cookie-store finders register themselves from init(). Imported
	// selectively rather than via browser/all: the text browsers and IE in
	// that umbrella package have no bearing on a scanner's session handoff.
	_ "github.com/browserutils/kooky/browser/brave"
	_ "github.com/browserutils/kooky/browser/chrome"
	_ "github.com/browserutils/kooky/browser/chromium"
	_ "github.com/browserutils/kooky/browser/edge"
	_ "github.com/browserutils/kooky/browser/firefox"
	_ "github.com/browserutils/kooky/browser/opera"
	_ "github.com/browserutils/kooky/browser/safari"
)

// Cookie is one decrypted cookie plus where it came from.
//
// SameSite is deliberately a string rather than an http.SameSite: the store
// reader does not report it (see [SameSiteUnknown]), and the exporters need to
// distinguish "the store said Lax" from "nobody knows" to avoid presenting a
// guess as a fact.
type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Secure   bool      `json:"secure"`
	HTTPOnly bool      `json:"http_only"`
	SameSite string    `json:"same_site"`
	Expires  time.Time `json:"expires,omitzero"`
	Created  time.Time `json:"created,omitzero"`

	Browser      string `json:"browser"`
	Profile      string `json:"profile"`
	ProfileLabel string `json:"profile_label,omitempty"`
	StoreFile    string `json:"store_file"`
}

// SameSiteUnknown is the SameSite value for a cookie whose attribute the store
// reader did not report. It is not a valid cookie attribute; the exporters
// resolve it to a concrete one and say so.
const SameSiteUnknown = ""

// ProfileName is the best display name for the profile the cookie came from:
// the label the browser shows, else the directory name. Shared with
// StoreInfo.profileName so the fallback cannot differ between the two.
func (c Cookie) ProfileName() string {
	return profileDisplayName(c.ProfileLabel, c.Profile)
}

// Session reports whether the cookie dies with the browser session (no expiry
// recorded), which means a consumer should not expect it to work tomorrow.
func (c Cookie) Session() bool { return c.Expires.IsZero() }

// Expired reports whether the cookie's expiry has passed at now. A session
// cookie is never expired by this test — its lifetime is not expressed here.
func (c Cookie) Expired(now time.Time) bool {
	return !c.Expires.IsZero() && c.Expires.Before(now)
}

// Query selects which cookies to read. A zero Query matches every cookie in
// every discoverable store, which is almost never what a caller wants; the CLI
// requires at least one domain.
type Query struct {
	// Domains to match, as hostnames. Empty matches every domain.
	Domains []string
	// Scope decides how a cookie's domain attribute is matched against Domains.
	Scope Scope
	// Names, when non-empty, keeps only cookies with one of these names.
	Names []string
	// Browsers, when non-empty, keeps only these browsers (lowercase, as
	// [SupportedBrowsers] reports them).
	Browsers []string
	// Profiles, when non-empty, keeps only stores whose profile directory or
	// human label matches one of these, case-insensitively.
	Profiles []string
	// UserDataDirs are extra Chromium user-data roots to read in addition to
	// the default install locations — the way to reach a Chrome for Testing,
	// Chrome Beta, or Playwright profile, none of which live where the
	// upstream finders look.
	UserDataDirs []string
	// WithStorage also reads each matching origin's local storage. It is
	// opt-in because it costs a staged copy of the profile's LevelDB store,
	// which the cookie read does not need.
	WithStorage bool
	// IncludeExpired keeps cookies whose expiry has already passed. They are
	// dropped by default: an expired cookie cannot authenticate anything, and
	// returning one invites a caller to believe it has a session when it does
	// not.
	IncludeExpired bool
	// Now is the clock for expiry decisions. Zero means time.Now().
	Now time.Time
	// NoPrompt refuses every cookie read that would ask the OS for approval
	// (on macOS: a store whose key is in the login keychain). Such a store is
	// reported as ProblemKeyringDenied without being opened, so an unattended
	// caller gets a coded answer instead of a dialog nobody will see. Local
	// and session storage need no key and are still read.
	NoPrompt bool
}

// keyringPromptTimeout bounds a read that may be waiting on an OS approval
// prompt. Generous, because the prompt is answered by a human who has to find
// the window and type a password; it exists so an unattended run cannot block
// forever on a dialog nobody will ever see. A var so tests can shorten it.
var keyringPromptTimeout = 2 * time.Minute

// errKeyringTimeout is a store read abandoned at keyringPromptTimeout.
var errKeyringTimeout = errors.New("keyring prompt not answered in time: the read was abandoned (a macOS approval dialog may still be on screen; deny it)")

// Problem classifies why a store yielded nothing, so a caller can branch
// without reading prose. It is the distinction between "look elsewhere for a
// session" and "ask the human to approve a keyring prompt".
type Problem string

const (
	// ProblemNone: the store was read.
	ProblemNone Problem = ""
	// ProblemKeyringDenied: the decryption key could not be read from the OS
	// keyring. On macOS this is the Keychain prompt being denied, dismissed, or
	// never shown because there is no desktop session.
	ProblemKeyringDenied Problem = "keyring_denied"
	// ProblemEncryptionUnsupported: the store uses an encryption scheme this
	// reader cannot undo — in practice Chrome 127+ App-Bound Encryption on
	// Windows, whose key only Chrome's elevation service can unwrap.
	//
	// The string matches apicontract.CodeBrowserEncryptionUnsupported verbatim,
	// as ProblemKeyringDenied matches CodeKeyringDenied: a driver reading
	// stores[].problem and error.code should not need a translation table to
	// see that they say the same thing.
	ProblemEncryptionUnsupported Problem = "browser_encryption_unsupported"
	// ProblemUnreadable: the store exists but could not be opened or parsed
	// (locked by a running browser in a way the reader cannot work around,
	// truncated file, permission denied on the file itself).
	ProblemUnreadable Problem = "unreadable"
	// ProblemDecryptFailed: rows were found and the key was available, but the
	// values did not decrypt. Usually a store written by a browser build whose
	// scheme has moved on.
	ProblemDecryptFailed Problem = "decrypt_failed"
)

// StoreResult is the outcome for a single cookie store.
type StoreResult struct {
	Store StoreInfo `json:"store"`
	Count int       `json:"count"`
	// StorageOrigins and StorageItems count what the local-storage read found
	// in this store, when one was asked for.
	StorageOrigins int `json:"storage_origins,omitempty"`
	StorageItems   int `json:"storage_items,omitempty"`
	// StorageProblem is why local storage could not be read, when it could
	// not. It is separate from Problem: a locked LevelDB store says nothing
	// about the cookies, which may have been read perfectly.
	StorageProblem string  `json:"storage_problem,omitempty"`
	Problem        Problem `json:"problem,omitempty"`
	// Detail is the underlying error text, for a human. Machine consumers
	// branch on Problem.
	Detail string `json:"detail,omitempty"`
}

// Result is everything one [Read] produced.
type Result struct {
	Cookies []Cookie `json:"cookies"`
	// Origins is the local and session storage of each matching origin,
	// present only when Query.WithStorage was set.
	Origins []Origin `json:"origins"`
	// Unreadable lists per-origin stores that exist but that no export short
	// of a profile clone can carry — IndexedDB, in practice. Reported because
	// an app whose session lives there restores its cookies perfectly and
	// still shows a login page.
	Unreadable []OriginStore `json:"unreadable"`
	Stores     []StoreResult `json:"stores"`
	// Matcher is the domain matcher the read was scoped by, built once from
	// Query.Domains and Query.Scope. Exposed so a caller that scopes further
	// work to the same domains (a profile clone, the resolved target list)
	// reuses it rather than rebuilding it. Not serialized.
	Matcher *Matcher `json:"-"`
	// Warnings are caveats about what was returned — fidelity limits that do
	// not make the result wrong, but do make it incomplete in a way the caller
	// should know about before trusting it.
	Warnings []string `json:"warnings"`
}

// Problem returns the most actionable problem across the stores read, or
// ProblemNone when every store was read cleanly.
//
// Ordering is by what the caller can do about it: a denied keyring is a prompt
// away from working, so it outranks an unsupported scheme that no retry fixes.
func (r Result) Problem() Problem {
	order := []Problem{
		ProblemKeyringDenied,
		ProblemDecryptFailed,
		ProblemEncryptionUnsupported,
		ProblemUnreadable,
	}
	for _, want := range order {
		for _, s := range r.Stores {
			if s.Problem == want {
				return want
			}
		}
	}
	return ProblemNone
}

// StorageItems counts the local and session storage entries read, across every
// origin. One definition, because the quantity was summed in the package and
// then summed again by the caller — and the caller's copy counted only local
// storage while calling itself the total.
func (r Result) StorageItems() int {
	n := 0
	for _, o := range r.Origins {
		n += o.ItemCount()
	}
	return n
}

// ProblemDetail returns the detail text of the first store carrying the
// result's governing problem, for an error message.
func (r Result) ProblemDetail() string {
	p := r.Problem()
	if p == ProblemNone {
		return ""
	}
	for _, s := range r.Stores {
		if s.Problem == p {
			return s.Detail
		}
	}
	return ""
}

// Read decrypts the cookies matching q from every store the query selects.
//
// A store that cannot be read does not fail the call: its failure is recorded
// in the corresponding [StoreResult] and the remaining stores are still read,
// because one locked Firefox profile is no reason to withhold the Chrome
// session the caller asked for. Inspect [Result.Problem] to find out whether an
// empty result means "nothing matched" or "nothing could be read".
func Read(ctx context.Context, q Query) (Result, error) {
	now := q.Now
	if now.IsZero() {
		now = time.Now()
	}

	// The matcher is built before discovery so a bad domain is reported before
	// any store is looked at.
	matcher, err := NewMatcher(q.Domains, q.Scope)
	if err != nil {
		return Result{}, err
	}

	stores, err := Discover(ctx, q)
	if err != nil {
		return Result{}, err
	}
	names := lowerSet(q.Names)

	res := Result{Cookies: []Cookie{}, Origins: []Origin{}, Unreadable: []OriginStore{}, Stores: []StoreResult{}, Matcher: matcher, Warnings: []string{}}
	sawSecure := false
	// Every Chromium profile of a browser shares one Safe Storage item, so the
	// --no-prompt keychain lookup is answered once per item rather than once
	// per store (keyringChecks dedupes the doctor's probe the same way).
	type keyringItem struct{ service, account string }
	type promptAnswer struct {
		prompts bool
		detail  string
	}
	wouldPrompt := map[keyringItem]promptAnswer{}

	for _, store := range stores {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		sr := StoreResult{Store: store}

		// A store already known to be unreadable is reported without an open
		// attempt: App-Bound Encryption fails per row with an error that reads
		// like a decryption bug, and saying so up front is clearer than
		// surfacing forty identical row failures.
		if store.AppBound {
			sr.Problem = ProblemEncryptionUnsupported
			sr.Detail = "Chrome App-Bound Encryption (Chrome 127+ on Windows): the key is held by Chrome's elevation service and cannot be unwrapped by another process"
			res.Stores = append(res.Stores, sr)
			continue
		}

		var (
			cookies []Cookie
			readErr error
		)
		prompts, detail := false, ""
		if q.NoPrompt {
			item := keyringItem{store.SafeStorage, store.KeyringAccount}
			answer, ok := wouldPrompt[item]
			if !ok {
				answer.prompts, answer.detail = keyringWouldPrompt(ctx, store)
				wouldPrompt[item] = answer
			}
			prompts, detail = answer.prompts, answer.detail
		}
		if prompts {
			sr.Problem, sr.Detail = ProblemKeyringDenied, detail
		} else {
			cookies, readErr = readStoreBounded(ctx, store, matcher, names)
			if err := ctx.Err(); err != nil {
				return res, err
			}
		}
		for _, c := range cookies {
			if !q.IncludeExpired && c.Expired(now) {
				continue
			}
			if c.Secure {
				sawSecure = true
			}
			res.Cookies = append(res.Cookies, c)
			sr.Count++
		}
		if readErr != nil {
			sr.Problem, sr.Detail = classifyReadError(readErr)
		}

		if q.WithStorage {
			origins, storageErr := readLocalStorage(ctx, store, matcher)
			if storageErr != nil {
				// Recorded against the store rather than failing the call: the
				// cookies above are already read, and a staged LevelDB that
				// would not open says nothing about them.
				sr.StorageProblem = storageErr.Error()
			}
			for _, o := range origins {
				sr.StorageOrigins++
				sr.StorageItems += o.ItemCount()
				res.Origins = append(res.Origins, o)
			}
			res.Unreadable = append(res.Unreadable, indexedDBStores(store.File, matcher)...)
		}
		res.Stores = append(res.Stores, sr)
	}

	sortCookies(res.Cookies)
	res.Warnings = append(res.Warnings, warningsFor(res, sawSecure)...)
	return res, nil
}

// readStoreFn is the store reader readStoreBounded runs; a var so a test can
// stand in a reader that blocks the way a pending keychain prompt does.
var readStoreFn = readStore

// readStoreBounded is readStore with a deadline the upstream reader lacks.
//
// The reader asks the OS keyring for the key on its first decrypt — on macOS by
// running /usr/bin/security (or the Keychain API in a cgo build) with no
// context, so a prompt nobody answers blocks it indefinitely, and so does an
// interrupt. The read runs in a goroutine and is abandoned at
// keyringPromptTimeout or on cancellation; the abandoned goroutine ends when
// the prompt is answered or the process exits.
func readStoreBounded(ctx context.Context, store StoreInfo, matcher *Matcher, names map[string]bool) ([]Cookie, error) {
	bounded, cancel := context.WithTimeout(ctx, keyringPromptTimeout)
	defer cancel()
	type outcome struct {
		cookies []Cookie
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		cookies, err := readStoreFn(bounded, store, matcher, names)
		done <- outcome{cookies, err}
	}()
	select {
	case o := <-done:
		return o.cookies, o.err
	case <-bounded.Done():
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errKeyringTimeout
	}
}

// readStore pulls the matching cookies out of one store.
//
// Domain and name matching run as metadata filters, which the reader applies
// before it decrypts a value. That is not only faster: it means a store with no
// matching domain never asks the OS keyring for a key, so querying a domain the
// browser has never seen does not raise a Keychain prompt.
func readStore(ctx context.Context, store StoreInfo, matcher *Matcher, names map[string]bool) ([]Cookie, error) {
	jar, err := store.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = jar.Close() }()

	filter := kooky.FilterFunc(func(c *kooky.Cookie) bool {
		if c == nil {
			return false
		}
		if len(names) > 0 && !names[strings.ToLower(c.Name)] {
			return false
		}
		return matcher.Match(c.Domain)
	})

	var (
		out  []Cookie
		errs []error
	)
	for c, err := range jar.TraverseCookies(filter) {
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if c == nil {
			continue
		}
		out = append(out, Cookie{
			Name:         c.Name,
			Value:        c.Value,
			Domain:       c.Domain,
			Path:         c.Path,
			Secure:       c.Secure,
			HTTPOnly:     c.HttpOnly,
			SameSite:     sameSiteName(c),
			Expires:      c.Expires,
			Created:      plausibleTime(c.Creation),
			Browser:      store.Browser,
			Profile:      store.Profile,
			ProfileLabel: store.Label,
			StoreFile:    store.File,
		})
		if err := ctx.Err(); err != nil {
			return out, err
		}
	}
	return out, errors.Join(errs...)
}

// plausibleTime passes a timestamp through, or returns the zero time when the
// value cannot be a real one.
//
// The Chromium reader derives a cookie's creation time from its SQLite rowid
// rather than from a stored timestamp, so what comes back is an arithmetic
// artifact: a live Chrome profile yields creation dates in the year 2185.
// Publishing that as `created` invites a caller to sort by it, filter on it, or
// show it to someone. A missing field is a fact; a date 160 years in the future
// is a lie, and the JSON field is omitzero precisely so it can be absent.
func plausibleTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	// The web's cookie era, with a day of slack for a clock that is ahead.
	const earliestYear = 1994
	if t.Year() < earliestYear || t.After(time.Now().AddDate(0, 0, 1)) {
		return time.Time{}
	}
	return t
}

// sameSiteName renders the cookie's SameSite attribute, or SameSiteUnknown when
// the store reader did not report one.
//
// The Chromium reader in the upstream library does not read the samesite
// column, so this is SameSiteUnknown for every Chromium cookie today. It is
// written as a mapping anyway so that a reader which starts reporting it is
// picked up without a change here, and so the exporters have one place to look.
func sameSiteName(c *kooky.Cookie) string {
	switch c.SameSite {
	case 2: // http.SameSiteLaxMode
		return "Lax"
	case 3: // http.SameSiteStrictMode
		return "Strict"
	case 4: // http.SameSiteNoneMode
		return "None"
	default:
		return SameSiteUnknown
	}
}

// classifyReadError turns the read errors from one store into a Problem.
//
// The signal is the upstream library's error text, because that is the only
// channel it offers: a keyring failure is wrapped into the per-row decryption
// error rather than surfaced as a typed error or a distinct return. The match
// is therefore on a substring of a message this package does not own. An
// upstream rewording degrades the classification to ProblemDecryptFailed —
// still a failure, still non-empty, never a silent success — which is why this
// is acceptable rather than merely expedient.
func classifyReadError(err error) (Problem, string) {
	detail := err.Error()
	if errors.Is(err, errKeyringTimeout) {
		return ProblemKeyringDenied, detail
	}
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "keyring password retrieval failed"):
		return ProblemKeyringDenied, detail
	case strings.Contains(lower, "app-bound"), strings.Contains(lower, "v20"):
		return ProblemEncryptionUnsupported, detail
	case strings.Contains(lower, "decryption failed"),
		strings.Contains(lower, "cipher"),
		strings.Contains(lower, "padding"):
		return ProblemDecryptFailed, detail
	default:
		return ProblemUnreadable, detail
	}
}

// warningsFor states the fidelity limits that apply to what was returned.
// Each one is a way a caller could reasonably believe the result is complete
// when it is not.
func warningsFor(res Result, sawSecure bool) []string {
	var out []string
	if len(res.Cookies) > 0 && sawSecure {
		out = append(out, "SameSite is not recorded by the store reader; exported cookies default to Lax. A cross-site flow needs --same-site none.")
	}
	for _, s := range res.Stores {
		if s.Store.WAL {
			out = append(out, fmt.Sprintf("%s/%s has unflushed writes (%s): a cookie set in the last few minutes may be missing. Quit the browser for a complete read.",
				s.Store.Browser, s.Store.profileName(), "Cookies-wal"))
		}
	}
	for _, s := range res.Stores {
		if s.StorageProblem == "" {
			continue
		}
		out = append(out, fmt.Sprintf("%s: local storage could not be read (%s); the cookies above are unaffected",
			s.Store.Describe(), s.StorageProblem))
	}
	if len(res.Unreadable) > 0 {
		var names []string
		for _, u := range res.Unreadable {
			names = append(names, fmt.Sprintf("%s (%s, %.0f KiB)", u.Origin, u.Kind, float64(u.Bytes)/1024))
		}
		out = append(out, fmt.Sprintf("%s holds IndexedDB that no cookie or storage export can carry: %s. If a restored session still shows a login page, this is why — use a profile clone instead.",
			plural(len(res.Unreadable), "origin", "origins"), strings.Join(names, ", ")))
	}
	for _, o := range res.Origins {
		if o.SessionNamespaces > 1 {
			out = append(out, fmt.Sprintf("%s had sessionStorage in %d tabs, merged into one set; sessionStorage is per-tab, so a key set differently in two tabs kept one value.",
				o.Origin, o.SessionNamespaces))
		}
	}
	sessionCount := 0
	for _, c := range res.Cookies {
		if c.Session() {
			sessionCount++
		}
	}
	if sessionCount > 0 {
		out = append(out, fmt.Sprintf("%d of %d cookies are session cookies with no recorded expiry; they may already be dead.", sessionCount, len(res.Cookies)))
	}
	return out
}

// plural renders "1 origin" / "2 origins" for a message.
func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// sortCookies puts the result in a stable order: domain, then name, then the
// store it came from, so two runs over an unchanged profile produce identical
// output and a diff between runs is meaningful.
func sortCookies(cookies []Cookie) {
	sort.SliceStable(cookies, func(i, j int) bool {
		a, b := cookies[i], cookies[j]
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Browser != b.Browser {
			return a.Browser < b.Browser
		}
		return a.Profile < b.Profile
	})
}

// lowerSet builds a lowercased lookup set, ignoring blanks.
func lowerSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, it := range items {
		if it = strings.ToLower(strings.TrimSpace(it)); it != "" {
			m[it] = true
		}
	}
	return m
}
