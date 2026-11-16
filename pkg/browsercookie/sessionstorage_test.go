package browsercookie

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
)

// writeSessionStorageDB builds a session-storage LevelDB in Chromium's layout.
// Note the layout difference from local storage: the .ldb files sit directly in
// "Session Storage", with no "leveldb" subdirectory.
func writeSessionStorageDB(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	profile := t.TempDir()
	cookieFile := filepath.Join(profile, "Cookies")
	writeFile(t, cookieFile, "db")

	dir := filepath.Join(profile, sessionStorageDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
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

func TestEachStoreOwnsItsLevelDBLayout(t *testing.T) {
	// Local storage nests its database under "leveldb"; session storage does
	// not. Assuming one layout for both finds nothing for the other and
	// reports it as "this origin has no session storage" — which is how this
	// was first shipped and caught.
	if got := localStorageLevelDBPath("/p"); got != filepath.Join("/p", localStorageDirName, "leveldb") {
		t.Errorf("local storage path = %q", got)
	}
	if got := sessionStorageLevelDBPath("/p"); got != filepath.Join("/p", sessionStorageDirName) {
		t.Errorf("session storage path = %q, want no leveldb subdirectory", got)
	}
	// And the clone descriptors carry each store's own path, so a name cannot
	// be paired with the other store's layout or prune pass.
	if got := localStorageClone.path("/p"); got != localStorageLevelDBPath("/p") {
		t.Errorf("localStorageClone.path = %q", got)
	}
	if got := sessionStorageClone.path("/p"); got != sessionStorageLevelDBPath("/p") {
		t.Errorf("sessionStorageClone.path = %q", got)
	}
}

func TestReadSessionStorageMergesTabsPerOrigin(t *testing.T) {
	// sessionStorage is per TAB: one origin has as many namespaces as it has
	// open tabs. Nothing in the store says which tab a caller means, so they
	// are merged and the count is reported.
	cookieFile := writeSessionStorageDB(t, map[string][]byte{
		"version":                                 []byte("1"),
		"namespace-aaaa_bbbb-https://acme.test/":  []byte("10"),
		"namespace-cccc_dddd-https://acme.test/":  []byte("11"),
		"namespace-eeee_ffff-https://other.test/": []byte("20"),
		"map-10-token":                            latin1Value("from-tab-one"),
		"map-11-locale":                           utf16Value("日本語"),
		"map-11-multi-word-key":                   latin1Value("kept"),
		"map-20-secret":                           latin1Value("other-origin"),
	})
	matcher, err := NewMatcher([]string{"acme.test"}, ScopeHost)
	if err != nil {
		t.Fatal(err)
	}
	store := StoreInfo{Browser: "chrome", Family: FamilyChromium, File: cookieFile}

	got, namespaces, err := readSessionStorage(context.Background(), store, matcher)
	if err != nil {
		t.Fatalf("readSessionStorage: %v", err)
	}
	items := got["https://acme.test"]
	if len(items) != 3 {
		t.Fatalf("got %+v, want three merged entries", items)
	}
	byName := map[string]string{}
	for _, it := range items {
		byName[it.Name] = it.Value
	}
	if byName["token"] != "from-tab-one" || byName["locale"] != "日本語" {
		t.Errorf("entries wrong: %v", byName)
	}
	if byName["multi-word-key"] != "kept" {
		t.Errorf("a key containing dashes was lost: %v", byName)
	}
	if namespaces["https://acme.test"] != 2 {
		t.Errorf("merged %d namespaces, want 2", namespaces["https://acme.test"])
	}
	if _, ok := got["https://other.test"]; ok {
		t.Error("another origin's session storage was returned")
	}
}

func TestReadSessionStorageMissingDirIsNotAnError(t *testing.T) {
	profile := t.TempDir()
	cookieFile := filepath.Join(profile, "Cookies")
	writeFile(t, cookieFile, "db")
	matcher, _ := NewMatcher([]string{"acme.test"}, ScopeHost)
	got, _, err := readSessionStorage(context.Background(), StoreInfo{File: cookieFile}, matcher)
	if err != nil || len(got) != 0 {
		t.Errorf("got (%v, %v), want nothing and no error", got, err)
	}
}

func TestParseSessionNamespaceKey(t *testing.T) {
	// The tab uuid separates its fields with underscores, so the first dash
	// after the prefix ends it — which matters because an origin may itself
	// contain a dash.
	origin, ok := parseSessionNamespaceKey([]byte("namespace-02efdadf_83dc_4222_8093_f06b4b1bec5b-https://demo-sit.acme.test/"))
	if !ok || origin != "https://demo-sit.acme.test" {
		t.Errorf("parseSessionNamespaceKey = (%q, %v)", origin, ok)
	}
	for _, bad := range []string{"namespace-", "namespace-nodash", "version", "map-1-k"} {
		if _, ok := parseSessionNamespaceKey([]byte(bad)); ok {
			t.Errorf("parseSessionNamespaceKey(%q) accepted a malformed key", bad)
		}
	}
}

func TestParseSessionMapKey(t *testing.T) {
	// Only the id's digits are consumed: entry names routinely contain dashes.
	id, name, ok := parseSessionMapKey([]byte("map-1195-grok-main-thread-watch-tab"))
	if !ok || id != "1195" || name != "grok-main-thread-watch-tab" {
		t.Errorf("parseSessionMapKey = (%q, %q, %v)", id, name, ok)
	}
	for _, bad := range []string{"map-", "map-abc-key", "map-12-", "namespace-x-y"} {
		if _, _, ok := parseSessionMapKey([]byte(bad)); ok {
			t.Errorf("parseSessionMapKey(%q) accepted a malformed key", bad)
		}
	}
}
