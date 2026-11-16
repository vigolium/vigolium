package browsercookie

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/syndtr/goleveldb/leveldb"
)

// latin1Key builds a value key in Chromium's layout: `_<origin>\x00\x01<name>`.
func latin1Key(origin, name string) []byte {
	key := append([]byte(localStorageKeyPrefix), origin...)
	key = append(key, 0x00, encodingLatin1)
	return append(key, name...)
}

// latin1Value encodes a value the way Chromium does for a Latin-1 string.
func latin1Value(v string) []byte {
	return append([]byte{encodingLatin1}, v...)
}

// utf16Value encodes a value as little-endian UTF-16 with Chromium's marker.
func utf16Value(v string) []byte {
	out := []byte{encodingUTF16}
	for _, unit := range utf16.Encode([]rune(v)) {
		out = append(out, byte(unit), byte(unit>>8))
	}
	return out
}

// writeLocalStorageDB builds a LevelDB store in Chromium's local-storage
// layout under a profile directory, and returns the profile's cookie path.
func writeLocalStorageDB(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	profile := t.TempDir()
	cookieFile := filepath.Join(profile, "Cookies")
	writeFile(t, cookieFile, "db")

	dir := filepath.Join(profile, localStorageDirName, "leveldb")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	for k, v := range entries {
		if err := db.Put([]byte(k), v, nil); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return cookieFile
}

func TestReadLocalStorageParsesChromiumLayout(t *testing.T) {
	cookieFile := writeLocalStorageDB(t, map[string][]byte{
		"VERSION":                    []byte("1"),
		"META:https://app.acme.test": []byte("\x00\x00"),
		string(latin1Key("https://app.acme.test", "token")):  latin1Value("abc123"),
		string(latin1Key("https://app.acme.test", "locale")): utf16Value("日本語"),
		// A different origin that must not match a host-scoped query.
		string(latin1Key("https://other.test", "nope")): latin1Value("x"),
	})

	matcher, err := NewMatcher([]string{"app.acme.test"}, ScopeHost)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	store := StoreInfo{Browser: "chrome", Family: FamilyChromium, Profile: "Default", File: cookieFile}

	origins, err := readLocalStorage(context.Background(), store, matcher)
	if err != nil {
		t.Fatalf("readLocalStorage: %v", err)
	}
	if len(origins) != 1 {
		t.Fatalf("got %d origins, want 1: %+v", len(origins), origins)
	}
	got := origins[0]
	if got.Origin != "https://app.acme.test" {
		t.Errorf("origin = %q", got.Origin)
	}
	// Sorted by name, so locale precedes token.
	want := []StorageItem{{Name: "locale", Value: "日本語"}, {Name: "token", Value: "abc123"}}
	if len(got.LocalStorage) != len(want) {
		t.Fatalf("got %+v, want %+v", got.LocalStorage, want)
	}
	for i := range want {
		if got.LocalStorage[i] != want[i] {
			t.Errorf("item %d = %+v, want %+v", i, got.LocalStorage[i], want[i])
		}
	}
	// VERSION and META: are bookkeeping, not entries.
	for _, item := range got.LocalStorage {
		if item.Name == "VERSION" || strings.HasPrefix(item.Name, "META") {
			t.Errorf("bookkeeping key %q leaked into the entries", item.Name)
		}
	}
	if got.Browser != "chrome" || got.Profile != "Default" {
		t.Errorf("origin lost its provenance: %+v", got)
	}
}

func TestReadLocalStorageIsolatesByOriginNotCookieDomain(t *testing.T) {
	// Local storage is per origin: a cookie on .acme.test reaches every
	// subdomain, but app.acme.test's storage is not acme.test's. Treating them
	// like cookie domains would hand a caller another origin's tokens.
	cookieFile := writeLocalStorageDB(t, map[string][]byte{
		string(latin1Key("https://app.acme.test", "a")): latin1Value("1"),
		string(latin1Key("https://acme.test", "b")):     latin1Value("2"),
	})
	store := StoreInfo{Browser: "chrome", Family: FamilyChromium, File: cookieFile}

	hostOnly, err := NewMatcher([]string{"acme.test"}, ScopeHost)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	origins, err := readLocalStorage(context.Background(), store, hostOnly)
	if err != nil {
		t.Fatalf("readLocalStorage: %v", err)
	}
	if len(origins) != 1 || origins[0].Origin != "https://acme.test" {
		t.Fatalf("host scope should see only its own origin, got %+v", origins)
	}

	wide, err := NewMatcher([]string{"acme.test"}, ScopeSubdomains)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	origins, err = readLocalStorage(context.Background(), store, wide)
	if err != nil {
		t.Fatalf("readLocalStorage: %v", err)
	}
	if len(origins) != 2 {
		t.Errorf("--scope subdomains should collect both origins, got %+v", origins)
	}
}

func TestReadLocalStorageMissingDirIsNotAnError(t *testing.T) {
	// A profile with no local storage is ordinary, not broken.
	profile := t.TempDir()
	cookieFile := filepath.Join(profile, "Cookies")
	writeFile(t, cookieFile, "db")

	matcher, _ := NewMatcher([]string{"acme.test"}, ScopeHost)
	origins, err := readLocalStorage(context.Background(), StoreInfo{File: cookieFile}, matcher)
	if err != nil {
		t.Errorf("a missing store should be silent, got %v", err)
	}
	if len(origins) != 0 {
		t.Errorf("got %+v, want nothing", origins)
	}
}

func TestReadLocalStorageLeavesTheOriginalUntouched(t *testing.T) {
	// The read stages a copy precisely so a LevelDB open — which replays the
	// write-ahead log — cannot alter a profile the user is still browsing with.
	cookieFile := writeLocalStorageDB(t, map[string][]byte{
		string(latin1Key("https://acme.test", "k")): latin1Value("v"),
	})
	dir := filepath.Join(filepath.Dir(cookieFile), localStorageDirName, "leveldb")
	before := dirFingerprint(t, dir)

	matcher, _ := NewMatcher([]string{"acme.test"}, ScopeHost)
	if _, err := readLocalStorage(context.Background(), StoreInfo{File: cookieFile}, matcher); err != nil {
		t.Fatalf("readLocalStorage: %v", err)
	}
	if after := dirFingerprint(t, dir); after != before {
		t.Errorf("the profile's store changed:\n before %s\n after  %s", before, after)
	}
}

func TestCopyLevelDBDirSkipsTheLockFile(t *testing.T) {
	// LOCK is the file a running browser holds; copying it would reproduce the
	// contention the copy exists to avoid.
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "CURRENT"), "MANIFEST-000001\n")
	writeFile(t, filepath.Join(src, "LOCK"), "")
	dst := t.TempDir()
	if err := copyLevelDBDir(src, dst); err != nil {
		t.Fatalf("copyLevelDBDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "CURRENT")); err != nil {
		t.Errorf("CURRENT was not staged: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "LOCK")); err == nil {
		t.Error("LOCK should not be staged")
	}
	// A staged copy holds the same secrets as the original.
	st, err := os.Stat(filepath.Join(dst, "CURRENT"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("staged file mode = %04o, want 0600", perm)
	}
}

func TestParseLocalStorageKey(t *testing.T) {
	origin, name, ok := parseLocalStorageKey(latin1Key("https://acme.test", "token"))
	if !ok || origin != "https://acme.test" || name != "token" {
		t.Errorf("parseLocalStorageKey = (%q, %q, %v)", origin, name, ok)
	}
	for _, bad := range [][]byte{
		nil,
		[]byte("_"),
		[]byte("VERSION"),
		[]byte("_https://acme.test"),    // no separator
		append([]byte("_acme"), 0x00),   // nothing after the separator
		append([]byte{0x00}, "acme"...), // wrong prefix
	} {
		if _, _, ok := parseLocalStorageKey(bad); ok {
			t.Errorf("parseLocalStorageKey(%q) accepted a malformed key", bad)
		}
	}
}

func TestDecodeDOMStorageString(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{latin1Value("plain"), "plain"},
		{utf16Value("日本語"), "日本語"},
		{utf16Value("emoji 🙂"), "emoji 🙂"}, // a surrogate pair
		{nil, ""},
		// No recognized marker: valid UTF-8 is returned rather than discarded.
		{[]byte("already text"), "already text"},
	}
	for _, c := range cases {
		if got := decodeDOMStorageString(c.in); got != c.want {
			t.Errorf("decodeDOMStorageString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// An odd trailing byte cannot start a UTF-16 code unit and must not panic.
	if got := decodeDOMStorageString([]byte{encodingUTF16, 'a'}); got == "" {
		t.Log("odd-length UTF-16 payload decoded to empty, which is acceptable")
	}
}

func TestOriginHost(t *testing.T) {
	cases := map[string]string{
		"https://app.acme.test":     "app.acme.test",
		"http://acme.test:8080":     "acme.test",
		"https://ACME.test":         "acme.test",
		"file:///Users/x":           "",
		"chrome-extension://abcdef": "abcdef",
		"acme.test":                 "", // no scheme: not an origin
	}
	for in, want := range cases {
		if got := originHost(in); got != want {
			t.Errorf("originHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatCarriesStorage(t *testing.T) {
	for _, f := range []Format{FormatPlaywright, FormatJSON, FormatJSONL} {
		if !FormatCarriesStorage(f) {
			t.Errorf("%s should carry storage", f)
		}
	}
	for _, f := range []Format{FormatNetscape, FormatHeader} {
		if FormatCarriesStorage(f) {
			t.Errorf("%s is a cookie-only wire format", f)
		}
	}
}

// dirFingerprint summarizes a directory's files, names and sizes, so a test can
// assert nothing in it changed.
func dirFingerprint(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var sb strings.Builder
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if e.Name() == "LOCK" {
			continue // its size is 0 either way; its mtime is not ours to assert
		}
		_, _ = sb.WriteString(e.Name())
		_, _ = sb.WriteString(":")
		_, _ = sb.WriteString(string(rune('0' + info.Size()%10)))
		_, _ = sb.WriteString(" ")
	}
	return sb.String()
}

func TestSplitStorageKeySeparatesPartitionMetadata(t *testing.T) {
	// Chromium serializes third-party storage as `<origin>/^0<top-level site>`.
	// Treating the whole string as an origin would both fail to match the host
	// and, if exported, restore another site's data as first-party.
	cases := []struct {
		in              string
		origin, topSite string
	}{
		{"https://acme.test", "https://acme.test", ""},
		{"https://widget.test/^0https://app.acme.test", "https://widget.test", "https://app.acme.test"},
		{"chrome-untrusted://new-tab-page/^0chrome://new-tab-page", "chrome-untrusted://new-tab-page", "chrome://new-tab-page"},
		{"https://widget.test/^1", "https://widget.test", "(opaque)"},
	}
	for _, c := range cases {
		origin, topSite := splitStorageKey(c.in)
		if origin != c.origin || topSite != c.topSite {
			t.Errorf("splitStorageKey(%q) = (%q, %q), want (%q, %q)", c.in, origin, topSite, c.origin, c.topSite)
		}
	}
}

func TestReadLocalStorageMarksPartitionedOriginsAndKeepsThemOutOfPlaywright(t *testing.T) {
	cookieFile := writeLocalStorageDB(t, map[string][]byte{
		string(latin1Key("https://acme.test", "first")):                         latin1Value("1"),
		string(latin1Key("https://acme.test/^0https://embedder.test", "third")): latin1Value("2"),
	})
	matcher, _ := NewMatcher([]string{"acme.test"}, ScopeHost)
	origins, err := readLocalStorage(context.Background(), StoreInfo{File: cookieFile}, matcher)
	if err != nil {
		t.Fatalf("readLocalStorage: %v", err)
	}
	if len(origins) != 2 {
		t.Fatalf("got %d origins, want both the first-party and the partitioned one: %+v", len(origins), origins)
	}
	var firstParty, partitioned *Origin
	for i := range origins {
		if origins[i].Partitioned {
			partitioned = &origins[i]
		} else {
			firstParty = &origins[i]
		}
	}
	if firstParty == nil || partitioned == nil {
		t.Fatalf("expected one of each, got %+v", origins)
	}
	if partitioned.TopLevelSite != "https://embedder.test" {
		t.Errorf("TopLevelSite = %q", partitioned.TopLevelSite)
	}
	if partitioned.Origin != "https://acme.test" {
		t.Errorf("partitioned origin = %q, want the origin without its partition suffix", partitioned.Origin)
	}
	if n := PartitionedOrigins(origins); n != 1 {
		t.Errorf("PartitionedOrigins = %d, want 1", n)
	}

	// The storageState must carry the first-party store only.
	got := playwrightOrigins(origins)
	if len(got) != 1 {
		t.Fatalf("storageState carried %d origins, want 1: %+v", len(got), got)
	}
	if len(got[0].LocalStorage) != 1 || got[0].LocalStorage[0].Name != "first" {
		t.Errorf("storageState carried the wrong entry: %+v", got[0])
	}
}
