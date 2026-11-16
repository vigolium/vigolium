package browsercookie

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestChromiumProfileOfBothLayouts(t *testing.T) {
	cases := []struct {
		path        string
		wantRoot    string
		wantProfile string
	}{
		{filepath.Join("/ud", "Profile 3", "Network", "Cookies"), "/ud", "Profile 3"},
		{filepath.Join("/ud", "Default", "Cookies"), "/ud", "Default"},
	}
	for _, c := range cases {
		root, profile := chromiumProfileOf(c.path)
		if root != c.wantRoot || profile != c.wantProfile {
			t.Errorf("chromiumProfileOf(%q) = (%q, %q), want (%q, %q)", c.path, root, profile, c.wantRoot, c.wantProfile)
		}
	}
}

func TestChromiumStoresUnderFindsBothLayoutsAndRejectsEmptyRoot(t *testing.T) {
	root := t.TempDir()
	modern := filepath.Join(root, "Profile 1", "Network", "Cookies")
	legacyOnly := filepath.Join(root, "Profile 2", "Cookies")
	writeFile(t, modern, "db")
	writeFile(t, legacyOnly, "db")

	stores, err := chromiumStoresUnder(root)
	if err != nil {
		t.Fatalf("chromiumStoresUnder: %v", err)
	}
	if len(stores) != 2 {
		t.Fatalf("found %d stores, want 2: %+v", len(stores), stores)
	}
	for _, s := range stores {
		if !s.Explicit {
			t.Errorf("%s should be marked Explicit: it came from --user-data-dir", s.File)
		}
		// An explicitly-pathed store is read with Chrome's identity, which is
		// the keyring item Chrome, Chrome Beta and Chrome for Testing share.
		if s.Browser != "chrome" {
			t.Errorf("browser = %q, want chrome", s.Browser)
		}
	}

	if _, err := chromiumStoresUnder(t.TempDir()); err == nil {
		t.Error("a directory with no cookie store should be reported, not silently yield nothing")
	}
	if _, err := chromiumStoresUnder(filepath.Join(root, "does-not-exist")); err == nil {
		t.Error("a missing --user-data-dir should be an error")
	}
	if got, err := chromiumStoresUnder("  "); err != nil || got != nil {
		t.Errorf("a blank root should be ignored, got (%v, %v)", got, err)
	}
}

func TestChromiumStoresUnderAcceptsABareProfileDirectory(t *testing.T) {
	// What a Playwright launch with --user-data-dir produces: the root *is*
	// the profile, with no "Default" beneath it.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cookies"), "db")
	stores, err := chromiumStoresUnder(root)
	if err != nil {
		t.Fatalf("chromiumStoresUnder: %v", err)
	}
	if len(stores) != 1 {
		t.Fatalf("found %d stores, want 1", len(stores))
	}
}

func TestChromiumStoresUnderRejectsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notadir")
	writeFile(t, path, "x")
	if _, err := chromiumStoresUnder(path); err == nil {
		t.Error("--user-data-dir pointing at a file should be an error")
	}
}

func TestEnrichReadsProfileLabelFromLocalState(t *testing.T) {
	root := t.TempDir()
	cookies := filepath.Join(root, "Profile 3", "Network", "Cookies")
	writeFile(t, cookies, "db")
	writeFile(t, filepath.Join(root, "Local State"), `{
	  "profile": {
	    "info_cache": {
	      "Profile 3": {"name": "Work", "user_name": "ops@acme.test", "gaia_name": "Ops"}
	    },
	    "last_used": "Profile 3"
	  },
	  "os_crypt": {"encrypted_key": "RFBBUEk="}
	}`)

	info := StoreInfo{Browser: "chrome", Family: FamilyChromium, File: cookies}
	enrich(&info, nil)

	// "Profile 3" is what is on disk; "Work" is what the human knows. Without
	// this the --profile flag is unusable by anyone who did not count their
	// profile directories.
	if info.Label != "Work" {
		t.Errorf("Label = %q, want Work", info.Label)
	}
	if info.Account != "ops@acme.test" {
		t.Errorf("Account = %q, want ops@acme.test", info.Account)
	}
	if !info.Default {
		t.Error("last_used should mark the profile as default")
	}
	if info.AppBound {
		t.Error("a profile with only encrypted_key is not App-Bound")
	}
	if info.SafeStorage != "Chrome Safe Storage" {
		t.Errorf("SafeStorage = %q", info.SafeStorage)
	}
}

func TestEnrichDetectsAppBoundEncryption(t *testing.T) {
	// The presence of app_bound_encrypted_key is how an unreadable Chrome
	// 127+ profile is recognized before a read produces forty identical
	// decryption failures.
	root := t.TempDir()
	cookies := filepath.Join(root, "Default", "Network", "Cookies")
	writeFile(t, cookies, "db")
	writeFile(t, filepath.Join(root, "Local State"),
		`{"os_crypt": {"app_bound_encrypted_key": "QVBQQg=="}}`)

	info := StoreInfo{Browser: "chrome", Family: FamilyChromium, File: cookies}
	enrich(&info, nil)
	if !info.AppBound {
		t.Error("app_bound_encrypted_key should set AppBound")
	}
}

func TestEnrichSurvivesMalformedLocalState(t *testing.T) {
	// The label is a nicety. Failing the read over unparsable JSON would trade
	// the feature for the decoration.
	root := t.TempDir()
	cookies := filepath.Join(root, "Default", "Cookies")
	writeFile(t, cookies, "db")
	writeFile(t, filepath.Join(root, "Local State"), "{not json")

	info := StoreInfo{Browser: "chrome", Family: FamilyChromium, File: cookies}
	enrich(&info, nil)
	if info.Label != "" {
		t.Errorf("Label = %q, want empty", info.Label)
	}
}

func TestEnrichFlagsUnflushedWAL(t *testing.T) {
	root := t.TempDir()
	cookies := filepath.Join(root, "Default", "Cookies")
	writeFile(t, cookies, "db")
	writeFile(t, cookies+"-wal", "pending writes")

	info := StoreInfo{Browser: "chrome", Family: FamilyChromium, File: cookies}
	enrich(&info, nil)
	if !info.WAL {
		t.Error("a non-empty -wal sidecar should be reported: the reader does not consult it")
	}
}

func TestEnrichIgnoresEmptyWAL(t *testing.T) {
	root := t.TempDir()
	cookies := filepath.Join(root, "Default", "Cookies")
	writeFile(t, cookies, "db")
	writeFile(t, cookies+"-wal", "")

	info := StoreInfo{Browser: "chrome", Family: FamilyChromium, File: cookies}
	enrich(&info, nil)
	if info.WAL {
		t.Error("an empty -wal holds nothing and should not warn")
	}
}

func TestDropSupersededStoresPrefersTheModernLayout(t *testing.T) {
	// Chrome 96 moved the store and left the old file behind. Returning both
	// shows every cookie twice, with two different values and no way to tell
	// which the browser would send.
	stores := []StoreInfo{
		{Browser: "chrome", Family: FamilyChromium, Root: "/ud", Profile: "Default", File: "/ud/Default/Cookies"},
		{Browser: "chrome", Family: FamilyChromium, Root: "/ud", Profile: "Default", File: "/ud/Default/Network/Cookies"},
		{Browser: "chrome", Family: FamilyChromium, Root: "/ud", Profile: "Profile 2", File: "/ud/Profile 2/Cookies"},
		{Browser: "firefox", Family: FamilyFirefox, File: "/ff/cookies.sqlite"},
	}
	got := dropSupersededStores(stores)
	var files []string
	for _, s := range got {
		files = append(files, s.File)
	}
	want := []string{"/ud/Default/Network/Cookies", "/ud/Profile 2/Cookies", "/ff/cookies.sqlite"}
	if !slices.Equal(files, want) {
		t.Errorf("dropSupersededStores kept %v, want %v", files, want)
	}
}

func TestDropSupersededStoresKeepsLegacyWhenAlone(t *testing.T) {
	stores := []StoreInfo{
		{Browser: "chrome", Family: FamilyChromium, Root: "/ud", Profile: "Default", File: "/ud/Default/Cookies"},
	}
	if got := dropSupersededStores(stores); len(got) != 1 {
		t.Errorf("a profile with only the legacy store must keep it, got %+v", got)
	}
}

func TestFirefoxProfileLabelFromProfilesINI(t *testing.T) {
	root := t.TempDir()
	cookies := filepath.Join(root, "Profiles", "abc123.dev-edition", "cookies.sqlite")
	writeFile(t, cookies, "db")
	writeFile(t, filepath.Join(root, "profiles.ini"), `[Profile0]
Name=default
Path=Profiles/xyz789.default

[Profile1]
Name=Developer Edition
Path=Profiles/abc123.dev-edition
Default=1
`)
	if got := firefoxProfileLabel(cookies, "abc123.dev-edition"); got != "Developer Edition" {
		t.Errorf("firefoxProfileLabel = %q, want Developer Edition", got)
	}
}

func TestFirefoxProfileLabelMissingINI(t *testing.T) {
	root := t.TempDir()
	cookies := filepath.Join(root, "Profiles", "abc.default", "cookies.sqlite")
	writeFile(t, cookies, "db")
	if got := firefoxProfileLabel(cookies, "abc.default"); got != "" {
		t.Errorf("firefoxProfileLabel = %q, want empty with no profiles.ini", got)
	}
}

func TestMatchesProfileAcceptsLabelDirectoryOrDefault(t *testing.T) {
	info := StoreInfo{Profile: "Profile 3", Label: "Work", Default: true}
	for _, selector := range []string{"work", "WORK", "profile 3", "default"} {
		if !matchesProfile(info, []string{selector}) {
			t.Errorf("--profile %q should match %+v", selector, info)
		}
	}
	if matchesProfile(info, []string{"personal"}) {
		t.Error("an unrelated selector should not match")
	}
	if !matchesProfile(info, nil) {
		t.Error("no selector should match everything")
	}
}

func TestSafeStorageForKnownBrowsers(t *testing.T) {
	item, account := safeStorageFor("chrome")
	if item != "Chrome Safe Storage" || account != "Chrome" {
		t.Errorf("safeStorageFor(chrome) = (%q, %q)", item, account)
	}
	if item, _ := safeStorageFor("firefox"); item != "" {
		t.Errorf("a browser with no Chromium keyring item should report none, got %q", item)
	}
}

func TestSupportedBrowsersAllHaveOpeners(t *testing.T) {
	for _, name := range SupportedBrowsers() {
		if _, ok := storeOpeners[name]; !ok {
			t.Errorf("%s is advertised but has no reader", name)
		}
		if familyOf(name) == "" {
			t.Errorf("%s has no family", name)
		}
	}
}

func TestStoreInfoDescribe(t *testing.T) {
	cases := []struct {
		info StoreInfo
		want string
	}{
		{StoreInfo{Browser: "chrome", Profile: "Profile 3", Label: "Work"}, "chrome/Work (Profile 3)"},
		{StoreInfo{Browser: "chrome", Profile: "Default"}, "chrome/Default"},
		{StoreInfo{Browser: "safari"}, "safari/default"},
	}
	for _, c := range cases {
		if got := c.info.Describe(); got != c.want {
			t.Errorf("Describe() = %q, want %q", got, c.want)
		}
	}
}

func TestNeedsKeyringByFamily(t *testing.T) {
	if !(StoreInfo{Family: FamilyChromium}).NeedsKeyring() {
		t.Error("a Chromium store needs a keyring secret")
	}
	if (StoreInfo{Family: FamilyFirefox}).NeedsKeyring() {
		t.Error("a Firefox cookie store is not keyring-encrypted")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestSelectorErrorsAreTypedSoTheCLICanExitTwo(t *testing.T) {
	// An unknown --browser or an unusable --user-data-dir is a mistyped
	// command line, not a failed read. Typed so the CLI classifies it as a
	// usage error instead of a failure a driver would retry forever.
	_, err := Discover(context.Background(), Query{Browsers: []string{"netscape"}})
	var selector SelectorError
	if !errors.As(err, &selector) {
		t.Errorf("an unknown browser gave %v, want a SelectorError", err)
	}

	_, err = chromiumStoresUnder(filepath.Join(t.TempDir(), "nope"))
	if !errors.As(err, &selector) {
		t.Errorf("a missing --user-data-dir gave %v, want a SelectorError", err)
	}

	_, err = NewMatcher([]string{"  "}, ScopeHost)
	if !errors.As(err, &selector) {
		t.Errorf("an unusable domain gave %v, want a SelectorError", err)
	}

	_, err = ParseScope("sideways")
	if !errors.As(err, &selector) {
		t.Errorf("an unknown scope gave %v, want a SelectorError", err)
	}
}
