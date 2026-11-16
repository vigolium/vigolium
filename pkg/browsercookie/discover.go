package browsercookie

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/browserutils/kooky"
	"github.com/browserutils/kooky/browser/brave"
	"github.com/browserutils/kooky/browser/chrome"
	"github.com/browserutils/kooky/browser/chromium"
	"github.com/browserutils/kooky/browser/edge"
	"github.com/browserutils/kooky/browser/firefox"
	"github.com/browserutils/kooky/browser/opera"
	"github.com/browserutils/kooky/browser/safari"
)

// Browser families, which decide how a store is located and labelled.
const (
	FamilyChromium = "chromium"
	FamilyFirefox  = "firefox"
	FamilySafari   = "safari"
)

// SelectorError marks a query whose selectors cannot be satisfied — an unknown
// browser name, an unusable --user-data-dir — as opposed to a failure of the
// work itself.
//
// It is a type rather than a sentinel so the CLI can exit 2 (usage) instead of
// 1 (failed): the caller's fix is to correct the command line, and a driver
// that retries a usage error forever is the behaviour this prevents.
type SelectorError struct{ Err error }

func (e SelectorError) Error() string { return e.Err.Error() }
func (e SelectorError) Unwrap() error { return e.Err }

// selectorErrorf builds a SelectorError.
func selectorErrorf(format string, args ...any) error {
	return SelectorError{Err: fmt.Errorf(format, args...)}
}

// StoreInfo describes one cookie store on disk. It is a value, not a handle:
// discovery holds nothing open, and a store is reopened by path when it is
// actually read, so enumerating profiles costs no file locks and no keyring
// access.
type StoreInfo struct {
	// Browser is the lowercase browser name, as [SupportedBrowsers] reports it.
	Browser string `json:"browser"`
	// Family groups browsers that share a store format and key source.
	Family string `json:"family"`
	// Profile is the on-disk profile directory name ("Default", "Profile 3").
	Profile string `json:"profile,omitempty"`
	// Label is the name the user sees in the browser ("Work"), read from the
	// browser's own profile metadata. The whole point of reading it: nobody
	// knows which of their profiles is "Profile 3".
	Label string `json:"label,omitempty"`
	// Account is the signed-in account for the profile, when the browser
	// records one.
	Account string `json:"account,omitempty"`
	// Default reports whether this is the browser's default profile.
	Default bool `json:"default"`
	// File is the path to the cookie store.
	File string `json:"file"`
	// Root is the user-data directory the profile lives in (Chromium only).
	Root string `json:"root,omitempty"`
	// Explicit reports whether this store came from a caller-supplied
	// --user-data-dir rather than a default install location.
	Explicit bool `json:"explicit,omitempty"`
	// WAL reports that a write-ahead log sits beside the store with content in
	// it. The reader does not consult it, so recent writes may be invisible.
	WAL bool `json:"wal,omitempty"`
	// AppBound reports that the profile's key is held under Chrome's
	// App-Bound Encryption, which makes the store unreadable here.
	AppBound bool `json:"app_bound,omitempty"`
	// SafeStorage names the OS keyring item holding the decryption key, for
	// diagnostics. Empty for stores that need no key.
	SafeStorage string `json:"safe_storage,omitempty"`
	// KeyringAccount is the keyring item's account attribute.
	KeyringAccount string `json:"keyring_account,omitempty"`
}

// profileName returns the best display name for the profile: its label when the
// browser recorded one, otherwise the directory name.
func (s StoreInfo) profileName() string {
	return profileDisplayName(s.Label, s.Profile)
}

// profileDisplayName is the label-then-directory-then-"default" fallback, in
// one place so StoreInfo and Cookie cannot disagree about what a profile is
// called — including the literal "default", which otherwise had to be kept in
// step across a package boundary.
func profileDisplayName(label, dir string) string {
	if label != "" {
		return label
	}
	if dir != "" {
		return dir
	}
	return "default"
}

// Describe renders the store as one short human identifier.
func (s StoreInfo) Describe() string {
	name := s.profileName()
	if s.Label != "" && s.Profile != "" && s.Label != s.Profile {
		name = fmt.Sprintf("%s (%s)", s.Label, s.Profile)
	}
	return s.Browser + "/" + name
}

// NeedsKeyring reports whether reading this store requires a secret from the
// OS keyring, and so may raise an approval prompt.
func (s StoreInfo) NeedsKeyring() bool { return s.Family == FamilyChromium }

// storeOpener reconstructs a reader for one store file.
//
// Reopening by browser rather than by format is load-bearing: each browser
// package stamps its own keyring item name onto the store, and reading a Brave
// profile with Chrome's reader would ask the OS for the wrong key.
var storeOpeners = map[string]func(string, ...kooky.Filter) (kooky.CookieStore, error){
	"chrome":   chrome.CookieStore,
	"chromium": chromium.CookieStore,
	"brave":    brave.CookieStore,
	"edge":     edge.CookieStore,
	"opera":    opera.CookieStore,
	"firefox":  firefox.CookieStore,
	"safari":   safari.CookieStore,
}

// SupportedBrowsers returns the browsers this package can read, sorted.
func SupportedBrowsers() []string {
	out := make([]string, 0, len(storeOpeners))
	for name := range storeOpeners {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// familyOf groups a browser name by store format.
func familyOf(browser string) string {
	switch browser {
	case "firefox":
		return FamilyFirefox
	case "safari":
		return FamilySafari
	default:
		return FamilyChromium
	}
}

// safeStorageFor names the keyring item a Chromium-family browser keeps its
// key in. It mirrors the browser packages' own derivation; it is reported for
// diagnostics only, never used to fetch a key here.
func safeStorageFor(browser string) (item, account string) {
	switch browser {
	case "edge":
		account = "Microsoft Edge"
	case "opera":
		if runtime.GOOS == "darwin" {
			account = "Opera"
		} else {
			account = "Chromium"
		}
	case "chrome":
		account = "Chrome"
	case "chromium":
		account = "Chromium"
	case "brave":
		account = "Brave"
	default:
		return "", ""
	}
	// Linux and Windows builds of Edge and Opera fall back to the Chromium
	// item; macOS uses the branded one. The browser packages do the same.
	if runtime.GOOS != "darwin" && (browser == "edge") {
		account = "Chromium"
	}
	return account + " Safe Storage", account
}

// open constructs a reader for the store.
func (s StoreInfo) open() (kooky.CookieStore, error) {
	opener, ok := storeOpeners[s.Browser]
	if !ok {
		return nil, fmt.Errorf("no reader for browser %q", s.Browser)
	}
	return opener(s.File)
}

// Discover enumerates the cookie stores q selects, newest-looking first within
// each browser.
//
// Stores are found in two ways: the browser packages' knowledge of default
// install locations, and any roots the caller named in Query.UserDataDirs. The
// second exists because the interesting profiles often are not in the first —
// Chrome for Testing, Chrome Beta and Dev, and the throwaway profiles
// Playwright and Puppeteer create all live wherever the launcher put them.
func Discover(ctx context.Context, q Query) ([]StoreInfo, error) {
	wantBrowsers := lowerSet(q.Browsers)
	for name := range wantBrowsers {
		if _, ok := storeOpeners[name]; !ok {
			return nil, selectorErrorf("unsupported browser %q (have %s)", name, strings.Join(SupportedBrowsers(), ", "))
		}
	}

	var found []StoreInfo
	seen := make(map[string]bool)

	add := func(info StoreInfo) {
		if info.File == "" || seen[info.File] {
			return
		}
		// The finders report the paths a browser *would* use, not the ones it
		// has: an installed Chrome yields both <profile>/Cookies and
		// <profile>/Network/Cookies whether or not either exists. Listing a
		// path with no file behind it turns "this profile is where your
		// session lives" into a guess, and reading it produces an open error
		// that reads like a permissions problem.
		if !fileHasContent(info.File) {
			return
		}
		seen[info.File] = true
		found = append(found, info)
	}

	// Default install locations, via the registered finders.
	for store, err := range kooky.TraverseCookieStores(ctx) {
		if err != nil || store == nil {
			continue
		}
		info := StoreInfo{
			Browser: strings.ToLower(store.Browser()),
			Profile: store.Profile(),
			Default: store.IsDefaultProfile(),
			File:    store.FilePath(),
		}
		// The finder hands back a store handle; discovery reopens by path when
		// it reads, so release this one rather than leaking a descriptor per
		// profile on the machine.
		_ = store.Close()
		if _, known := storeOpeners[info.Browser]; !known {
			continue
		}
		add(info)
	}

	// Caller-supplied Chromium roots.
	for _, root := range q.UserDataDirs {
		stores, err := chromiumStoresUnder(root)
		if err != nil {
			return nil, err
		}
		for _, info := range stores {
			add(info)
		}
	}

	// One Local State read per user-data root, not per store: a Chrome root
	// with N profiles yields N stores, and every one of them was re-reading and
	// re-parsing the same file. It grows with profile.info_cache, and for
	// `kit cookies profiles` this is the command's only real I/O.
	states := map[string]localState{}
	enriched := make([]StoreInfo, 0, len(found))
	for _, info := range found {
		info.Family = familyOf(info.Browser)
		enrich(&info, states)
		if len(wantBrowsers) > 0 && !wantBrowsers[info.Browser] {
			continue
		}
		if !matchesProfile(info, q.Profiles) {
			continue
		}
		enriched = append(enriched, info)
	}
	out := dropSupersededStores(enriched)

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Browser != b.Browser {
			return a.Browser < b.Browser
		}
		// Default profile first: it is the one an operator means when they do
		// not say which.
		if a.Default != b.Default {
			return a.Default
		}
		return a.Profile < b.Profile
	})
	return out, nil
}

// dropSupersededStores removes a profile's legacy cookie store when the modern
// one is present.
//
// Chrome 96 moved cookies from <profile>/Cookies to <profile>/Network/Cookies
// and left the old file behind. Both still exist in plenty of long-lived
// profiles, and the stale one holds whatever the browser last wrote to it,
// years ago. Returning both means a caller sees each cookie twice, with two
// different values, and no way to tell which one the browser would actually
// send.
func dropSupersededStores(stores []StoreInfo) []StoreInfo {
	type key struct{ browser, root, profile string }
	modern := make(map[key]bool, len(stores))
	for _, s := range stores {
		if s.Family == FamilyChromium && isNetworkLayout(s.File) {
			modern[key{s.Browser, s.Root, s.Profile}] = true
		}
	}
	if len(modern) == 0 {
		return stores
	}
	out := make([]StoreInfo, 0, len(stores))
	for _, s := range stores {
		legacy := s.Family == FamilyChromium && !isNetworkLayout(s.File)
		if legacy && modern[key{s.Browser, s.Root, s.Profile}] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// matchesProfile reports whether the store satisfies a --profile selector,
// which may name the directory or the human label, case-insensitively.
func matchesProfile(info StoreInfo, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" {
			continue
		}
		if strings.ToLower(info.Profile) == w || strings.ToLower(info.Label) == w {
			return true
		}
		if w == "default" && info.Default {
			return true
		}
	}
	return false
}

// chromiumStoresUnder finds the cookie stores inside an explicit Chromium
// user-data directory.
//
// Both layouts are checked: Chrome 96 and later keep cookies in
// <profile>/Network/Cookies, earlier builds and some derivatives in
// <profile>/Cookies. A root that is itself a profile directory (what a
// Playwright launch with a bare --user-data-dir produces) is handled too.
func chromiumStoresUnder(root string) ([]StoreInfo, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, selectorErrorf("--user-data-dir %s: %w", root, err)
	}
	if st, err := os.Stat(abs); err != nil {
		return nil, selectorErrorf("--user-data-dir %s: %w", root, err)
	} else if !st.IsDir() {
		return nil, selectorErrorf("--user-data-dir %s: not a directory", root)
	}

	candidates := []string{
		filepath.Join(abs, "*", "Network", "Cookies"),
		filepath.Join(abs, "*", "Cookies"),
		filepath.Join(abs, "Network", "Cookies"),
		filepath.Join(abs, "Cookies"),
	}
	var out []StoreInfo
	seen := make(map[string]bool)
	for _, pattern := range candidates {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, selectorErrorf("--user-data-dir %s: %w", root, err)
		}
		for _, m := range matches {
			if seen[m] {
				continue
			}
			st, err := os.Stat(m)
			if err != nil || st.IsDir() {
				continue
			}
			seen[m] = true
			profileRoot, profile := chromiumProfileOf(m)
			out = append(out, StoreInfo{
				// A store found by path is read with Chrome's identity: that is
				// the keyring item Chrome, Chrome Beta, Chrome Dev and Chrome
				// for Testing all write under, and an automation profile built
				// with --use-mock-keychain decrypts without touching a keyring
				// at all.
				Browser:  "chrome",
				Profile:  profile,
				Default:  profile == "Default",
				File:     m,
				Root:     profileRoot,
				Explicit: true,
			})
		}
	}
	if len(out) == 0 {
		return nil, selectorErrorf("--user-data-dir %s: no cookie store found (expected <profile>/Network/Cookies)", root)
	}
	return out, nil
}

// chromiumProfileOf derives the user-data root and profile directory name from
// a Chromium cookie store path.
func chromiumProfileOf(cookiePath string) (root, profile string) {
	dir := profileDirOf(cookiePath)
	return filepath.Dir(dir), filepath.Base(dir)
}

// enrich fills in the facts that require looking beside the store: the profile
// label, whether a WAL sidecar holds unflushed writes, and whether the key is
// App-Bound.
func enrich(info *StoreInfo, states map[string]localState) {
	if wal := info.File + "-wal"; fileHasContent(wal) {
		info.WAL = true
	}
	switch info.Family {
	case FamilyChromium:
		if info.Root == "" {
			info.Root, info.Profile = chromiumProfileOf(info.File)
		}
		info.SafeStorage, info.KeyringAccount = safeStorageFor(info.Browser)
		state := cachedLocalState(info.Root, states)
		if p, ok := state.Profile.InfoCache[info.Profile]; ok {
			info.Label = cmp.Or(p.Name, p.GAIAName)
			info.Account = p.UserName
		}
		if state.Profile.LastUsed != "" && state.Profile.LastUsed == info.Profile {
			info.Default = true
		}
		info.AppBound = state.OSCrypt.AppBoundEncryptedKey != ""
	case FamilyFirefox:
		info.Label = firefoxProfileLabel(info.File, info.Profile)
	}
}

// fileHasContent reports whether path exists as a regular file with bytes in it.
func fileHasContent(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir() && st.Size() > 0
}

// localState is the slice of Chromium's "Local State" file this package reads:
// the profile display names, and whether the key is App-Bound.
type localState struct {
	Profile struct {
		InfoCache map[string]struct {
			Name     string `json:"name"`
			UserName string `json:"user_name"`
			GAIAName string `json:"gaia_name"`
		} `json:"info_cache"`
		LastUsed string `json:"last_used"`
	} `json:"profile"`
	OSCrypt struct {
		EncryptedKey         string `json:"encrypted_key"`
		AppBoundEncryptedKey string `json:"app_bound_encrypted_key"`
	} `json:"os_crypt"`
}

// localStateMaxBytes caps the read: "Local State" is tens of kilobytes of JSON
// in normal use, and a profile directory is not a trusted input just because it
// is in the user's home.
const localStateMaxBytes = 8 << 20 // 8 MiB

// cachedLocalState memoizes readLocalState by user-data root. A nil map reads
// through, so callers with one store need not build one.
func cachedLocalState(root string, states map[string]localState) localState {
	if states == nil {
		return readLocalState(root)
	}
	if state, ok := states[root]; ok {
		return state
	}
	state := readLocalState(root)
	states[root] = state
	return state
}

// readLocalState parses the user-data directory's "Local State". A missing or
// malformed file yields a zero value: the label is a nicety, and failing the
// whole read over it would trade the feature for the decoration.
func readLocalState(root string) localState {
	var state localState
	if root == "" {
		return state
	}
	path := filepath.Join(root, "Local State")
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() > localStateMaxBytes {
		return state
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return state
	}
	_ = json.Unmarshal(data, &state)
	return state
}

// firefoxProfileLabel resolves a Firefox profile directory to the name shown in
// the profile manager, via profiles.ini.
func firefoxProfileLabel(cookiePath, profileDir string) string {
	// <root>/Profiles/<dir>/cookies.sqlite, or <root>/<dir>/cookies.sqlite.
	dir := filepath.Dir(cookiePath)
	parent := filepath.Dir(dir)
	root := parent
	if strings.EqualFold(filepath.Base(parent), "Profiles") {
		root = filepath.Dir(parent)
	}
	f, err := os.Open(filepath.Join(root, "profiles.ini"))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	var name, path string
	flush := func() string {
		if path != "" && (strings.EqualFold(filepath.Base(path), profileDir) || strings.EqualFold(path, profileDir)) {
			return name
		}
		return ""
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			if got := flush(); got != "" {
				return got
			}
			name, path = "", ""
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			name = strings.TrimSpace(value)
		case "path":
			path = strings.TrimSpace(value)
		}
	}
	return flush()
}
