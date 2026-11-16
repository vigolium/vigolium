package browsercookie

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/uptrace/bun/driver/sqliteshim"
)

// writeCookieDB builds a cookie store shaped like Chromium's, with the columns
// the clone's rewrites touch.
func writeCookieDB(t *testing.T, path string, rows []cookieRow) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	db, err := sql.Open(sqliteshim.ShimName, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TABLE cookies (
		host_key TEXT, name TEXT, value TEXT, path TEXT,
		encrypted_value BLOB, is_persistent INTEGER, has_expires INTEGER, expires_utc INTEGER,
		is_secure INTEGER, is_httponly INTEGER
	)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, r := range rows {
		if _, err := db.Exec(
			`INSERT INTO cookies (host_key, name, value, path, encrypted_value, is_persistent, has_expires, expires_utc, is_secure, is_httponly)
			 VALUES (?, ?, '', ?, ?, ?, ?, ?, 1, 1)`,
			r.host, r.name, r.path, []byte("v10ENCRYPTED"), r.persistent, r.persistent, r.expires,
		); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
}

type cookieRow struct {
	host, name, path string
	persistent       int
	expires          int64
}

func TestCloneProfilePrunesRewritesAndCarriesIndexedDB(t *testing.T) {
	src := t.TempDir()
	profile := filepath.Join(src, "Default")
	cookieFile := filepath.Join(profile, "Cookies")
	writeCookieDB(t, cookieFile, []cookieRow{
		{host: ".acme.test", name: "session", path: "/", persistent: 0},
		{host: "acme.test", name: "pref", path: "/", persistent: 1, expires: chromeTime(time.Now().Add(24 * time.Hour))},
		{host: ".other.test", name: "leak", path: "/", persistent: 1, expires: chromeTime(time.Now().Add(24 * time.Hour))},
	})

	// Local storage for the target and a bystander.
	lsDir := filepath.Join(profile, localStorageDirName, "leveldb")
	if err := os.MkdirAll(lsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ls, err := leveldb.OpenFile(lsDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string][]byte{
		"VERSION": []byte("1"),
		string(latin1Key("https://acme.test", "keep")):  latin1Value("1"),
		string(latin1Key("https://other.test", "drop")): latin1Value("2"),
		localStorageMetaPrefix + "https://other.test":   []byte("x"),
	} {
		if err := ls.Put([]byte(k), v, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := ls.Close(); err != nil {
		t.Fatal(err)
	}

	// IndexedDB for the target and a bystander.
	for _, name := range []string{"https_acme.test_0", "https_other.test_0"} {
		dir := filepath.Join(profile, indexedDBDirName, name+indexedDBDirSuffix)
		writeFile(t, filepath.Join(dir, "CURRENT"), "MANIFEST-000001\n")
	}
	// Preferences must not be copied: it carries every visited site's settings.
	writeFile(t, filepath.Join(profile, "Preferences"), `{"profile":{"content_settings":{"other.test":1}}}`)

	cookies := []Cookie{
		{Domain: ".acme.test", Name: "session", Path: "/", Value: "SESSIONVALUE"},
		{Domain: "acme.test", Name: "pref", Path: "/", Value: "dark"},
		{Domain: ".other.test", Name: "leak", Path: "/", Value: "NOPE"},
	}
	store := StoreInfo{Browser: "chrome", Family: FamilyChromium, Profile: "Default", File: cookieFile, Root: src}
	matcher, err := NewMatcher([]string{"acme.test"}, ScopeSubdomains)
	if err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "clone")
	res, err := CloneProfile(context.Background(), store, matcher, cookies, dst)
	if err != nil {
		t.Fatalf("CloneProfile: %v", err)
	}

	if res.Cookies != 2 {
		t.Errorf("kept %d cookies, want 2", res.Cookies)
	}
	if res.SessionCookiesMadePersistent != 1 {
		t.Errorf("made %d session cookies persistent, want 1", res.SessionCookiesMadePersistent)
	}
	if res.IndexedDBOrigins != 1 {
		t.Errorf("copied %d IndexedDB origins, want 1", res.IndexedDBOrigins)
	}
	if res.LocalStorageKeys != 1 {
		t.Errorf("kept %d localStorage keys, want 1", res.LocalStorageKeys)
	}

	// Preferences is the leak that survived every other prune.
	if _, err := os.Stat(filepath.Join(dst, cloneProfileDir, "Preferences")); !os.IsNotExist(err) {
		t.Error("Preferences must not be copied: it carries other sites' settings")
	}
	// The bystander's IndexedDB must not be there.
	if _, err := os.Stat(filepath.Join(dst, cloneProfileDir, indexedDBDirName, "https_other.test_0"+indexedDBDirSuffix)); !os.IsNotExist(err) {
		t.Error("another origin's IndexedDB was copied")
	}
	if _, err := os.Stat(filepath.Join(dst, cloneReadmeName)); err != nil {
		t.Errorf("the clone should explain itself: %v", err)
	}

	assertClonedCookies(t, filepath.Join(dst, cloneProfileDir, "Cookies"))

	// Every file owner-only: the directory is a session.
	_ = filepath.WalkDir(dst, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // walk errors are not the assertion
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s is mode %04o, want 0600", path, perm)
		}
		return nil
	})
}

// assertClonedCookies checks the two rewrites the clone depends on.
func assertClonedCookies(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open(sqliteshim.ShimName, path)
	if err != nil {
		t.Fatalf("open clone: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Query(`SELECT host_key, name, value, encrypted_value, is_persistent, expires_utc FROM cookies ORDER BY name`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	seen := map[string]bool{}
	for rows.Next() {
		var (
			host, name, value string
			enc               []byte
			persistent        int
			expires           int64
		)
		if err := rows.Scan(&host, &name, &value, &enc, &persistent, &expires); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen[name] = true
		if strings.Contains(host, "other.test") {
			t.Errorf("another site's cookie survived pruning: %s", host)
		}
		// Plaintext, with encrypted_value cleared: an automation launch has no
		// keyring key, and a row it cannot decrypt it DELETES.
		if value == "" {
			t.Errorf("%s has no plaintext value; a launched browser will drop it", name)
		}
		if len(enc) != 0 {
			t.Errorf("%s still carries encrypted_value (%d bytes)", name, len(enc))
		}
		// Every row persistent: a cookie with no expiry is discarded at startup.
		if persistent != 1 {
			t.Errorf("%s is not persistent; the browser will discard it on startup", name)
		}
		if expires <= chromeTime(time.Now()) {
			t.Errorf("%s expires at %d, which is not in the future", name, expires)
		}
	}
	if !seen["session"] || !seen["pref"] {
		t.Errorf("expected both in-scope cookies, got %v", seen)
	}
}

func TestCloneProfileRefusesNonChromium(t *testing.T) {
	// The clone's whole value is that Chromium can open it.
	matcher, _ := NewMatcher([]string{"acme.test"}, ScopeHost)
	store := StoreInfo{Browser: "firefox", Family: FamilyFirefox, File: filepath.Join(t.TempDir(), "cookies.sqlite")}
	_, err := CloneProfile(context.Background(), store, matcher, nil, filepath.Join(t.TempDir(), "clone"))
	var selector SelectorError
	if !errors.As(err, &selector) {
		t.Errorf("got %v, want a SelectorError", err)
	}
}

func TestCloneProfileRefusesAppBound(t *testing.T) {
	matcher, _ := NewMatcher([]string{"acme.test"}, ScopeHost)
	store := StoreInfo{Browser: "chrome", Family: FamilyChromium, AppBound: true, File: filepath.Join(t.TempDir(), "Cookies")}
	if _, err := CloneProfile(context.Background(), store, matcher, nil, filepath.Join(t.TempDir(), "clone")); err == nil {
		t.Error("an App-Bound profile would clone cookies nothing can decrypt")
	}
}

func TestCheckCloneDestinationRefusesAnOccupiedTarget(t *testing.T) {
	// A clone half of which is someone else's profile is worse than no clone,
	// and this is the one output a caller is invited to point a browser at.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "something"), "x")
	var selector SelectorError
	if _, err := checkCloneDestination(dir); !errors.As(err, &selector) {
		t.Errorf("got %v, want a SelectorError for a non-empty directory", err)
	}

	file := filepath.Join(t.TempDir(), "file")
	writeFile(t, file, "x")
	if _, err := checkCloneDestination(file); !errors.As(err, &selector) {
		t.Errorf("got %v, want a SelectorError for a file", err)
	}

	fresh := filepath.Join(t.TempDir(), "new", "deeper")
	if replace, err := checkCloneDestination(fresh); err != nil || replace {
		t.Errorf("a new path is accepted and not replaced: replace=%v err=%v", replace, err)
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Error("checking the destination must not create it")
	}
	if replace, err := checkCloneDestination(t.TempDir()); err != nil || !replace {
		t.Errorf("an empty directory is accepted for replacement: replace=%v err=%v", replace, err)
	}
}

// cloneFixture is a one-site-plus-bystander Chromium profile for the staging
// tests.
func cloneFixture(t *testing.T) (StoreInfo, *Matcher, []Cookie) {
	t.Helper()
	src := t.TempDir()
	cookieFile := filepath.Join(src, "Default", "Cookies")
	writeCookieDB(t, cookieFile, []cookieRow{
		{host: ".acme.test", name: "session", path: "/", persistent: 1, expires: chromeTime(time.Now().Add(time.Hour))},
		{host: ".other.test", name: "leak", path: "/", persistent: 1, expires: chromeTime(time.Now().Add(time.Hour))},
	})
	matcher, err := NewMatcher([]string{"acme.test"}, ScopeSubdomains)
	if err != nil {
		t.Fatal(err)
	}
	store := StoreInfo{Browser: "chrome", Family: FamilyChromium, Profile: "Default", File: cookieFile, Root: src}
	return store, matcher, []Cookie{{Domain: ".acme.test", Name: "session", Path: "/", Value: "SESSIONVALUE"}}
}

// requireOnlyEntries fails unless dir holds exactly names: no staging
// directory may outlive a clone, successful or not.
func requireOnlyEntries(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != strings.Join(names, ",") {
		t.Errorf("%s holds %v, want exactly %v", dir, got, names)
	}
}

// An interrupted clone (ctx cancelled mid-build) leaves nothing behind: not
// the destination, and not the staging directory with every site's cookies.
func TestCloneProfileInterruptedLeavesNothing(t *testing.T) {
	store, matcher, cookies := cloneFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "clone")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CloneProfile(ctx, store, matcher, cookies, dst); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	requireOnlyEntries(t, parent)
}

// A clone that fails part-way (a cookie store that is not a database) leaves
// nothing behind either, and an empty destination it was asked to fill is
// left as it was.
func TestCloneProfileFailureRemovesStaging(t *testing.T) {
	store, matcher, cookies := cloneFixture(t)
	writeFile(t, store.File, "not a sqlite database")
	parent := t.TempDir()
	dst := filepath.Join(parent, "clone")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := CloneProfile(context.Background(), store, matcher, cookies, dst); err == nil {
		t.Fatal("a corrupt cookie store should fail the clone")
	}
	requireOnlyEntries(t, parent, "clone")
	requireOnlyEntries(t, dst)
}

// A successful clone replaces an empty destination by rename; the result is
// owner-only and no staging directory is left beside it.
func TestCloneProfileRenamesIntoPlace(t *testing.T) {
	store, matcher, cookies := cloneFixture(t)
	parent := t.TempDir()
	dst := filepath.Join(parent, "clone")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := CloneProfile(context.Background(), store, matcher, cookies, dst)
	if err != nil {
		t.Fatalf("CloneProfile: %v", err)
	}
	if res.Dir != dst || res.Cookies != 1 {
		t.Errorf("res = %+v, want dir %s with 1 cookie", res, dst)
	}
	requireOnlyEntries(t, parent, "clone")
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o700 {
		t.Errorf("clone directory is mode %04o, want 0700", perm)
	}
	readme, err := os.ReadFile(filepath.Join(dst, cloneReadmeName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), dst) || strings.Contains(string(readme), ".vigolium-clone-") {
		t.Error("the README names the final directory, never the staging one")
	}
}

// pruneLocalStorage keeps only VERSION and in-scope rows. Every other row —
// an out-of-scope METAACCESS: access record, a malformed value row, a shape
// nobody has seen — is deleted.
func TestPruneLocalStorageDefaultDenies(t *testing.T) {
	db, err := leveldb.OpenFile(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	keep := []string{
		"VERSION",
		string(latin1Key("https://acme.test", "token")),
		localStorageMetaPrefix + "https://acme.test",
		"METAACCESS:https://acme.test",
	}
	drop := []string{
		string(latin1Key("https://other.test", "token")),
		localStorageMetaPrefix + "https://other.test",
		"METAACCESS:https://other.test",
		"_",                                // a value row too short to name an origin
		"SOMETHING_NEW:https://other.test", // a shape this code has never seen
	}
	for _, k := range append(append([]string{}, keep...), drop...) {
		if err := db.Put([]byte(k), []byte("v"), nil); err != nil {
			t.Fatal(err)
		}
	}
	matcher, _ := NewMatcher([]string{"acme.test"}, ScopeHost)
	kept, err := pruneLocalStorage(db, matcher)
	if err != nil {
		t.Fatalf("pruneLocalStorage: %v", err)
	}
	if kept != 1 {
		t.Errorf("kept %d value rows, want 1", kept)
	}
	for _, k := range keep {
		if _, err := db.Get([]byte(k), nil); err != nil {
			t.Errorf("%q was deleted, want kept", k)
		}
	}
	for _, k := range drop {
		if _, err := db.Get([]byte(k), nil); err == nil {
			t.Errorf("%q survived, want deleted", k)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteScopedLocalStateCarriesOnlyTheKey(t *testing.T) {
	// The original Local State also holds profile.info_cache — the operator's
	// profile names and signed-in addresses — which the clone has no use for.
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "Local State"), `{
	  "profile": {"info_cache": {"Default": {"user_name": "someone@acme.test"}}},
	  "os_crypt": {"encrypted_key": "RFBBUEl4eHg="}
	}`)
	dst := t.TempDir()
	if err := writeScopedLocalState(src, dst); err != nil {
		t.Fatalf("writeScopedLocalState: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dst, "Local State"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "someone@acme.test") {
		t.Errorf("the clone's Local State leaked an account address: %s", data)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := doc["profile"]; ok {
		t.Error("the profile section should not be carried")
	}
	osCrypt, ok := doc["os_crypt"].(map[string]any)
	if !ok || osCrypt["encrypted_key"] != "RFBBUEl4eHg=" {
		t.Errorf("the encryption key was not carried: %v", doc)
	}
}

func TestWriteScopedLocalStateSkipsWhenThereIsNoKey(t *testing.T) {
	// macOS and Linux keep the key in the OS keyring, so the clone needs
	// nothing from this file at all.
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "Local State"), `{"profile":{"info_cache":{}}}`)
	dst := t.TempDir()
	if err := writeScopedLocalState(src, dst); err != nil {
		t.Fatalf("writeScopedLocalState: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "Local State")); !os.IsNotExist(err) {
		t.Error("with no encrypted_key the clone should get no Local State")
	}
}

func TestPruneSessionStorageKeepsOnlyInScopeNamespaces(t *testing.T) {
	dir := t.TempDir()
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string][]byte{
		"version":                                 []byte("1"),
		"namespace-aaaa_bbbb-https://acme.test/":  []byte("10"),
		"namespace-cccc_dddd-https://other.test/": []byte("20"),
		"map-10-token":                            latin1Value("keep"),
		"map-10-multi-word-key":                   latin1Value("keep"),
		"map-20-secret":                           latin1Value("drop"),
	}
	for k, v := range entries {
		if err := db.Put([]byte(k), v, nil); err != nil {
			t.Fatal(err)
		}
	}
	matcher, _ := NewMatcher([]string{"acme.test"}, ScopeHost)
	kept, err := pruneSessionStorage(db, matcher)
	if err != nil {
		t.Fatalf("pruneSessionStorage: %v", err)
	}
	if kept != 2 {
		t.Errorf("kept %d map entries, want 2", kept)
	}
	if _, err := db.Get([]byte("map-20-secret"), nil); err == nil {
		t.Error("another origin's session entry survived")
	}
	if _, err := db.Get([]byte("map-10-multi-word-key"), nil); err != nil {
		t.Error("a key containing dashes was dropped; the map id parse is wrong")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestChromeTimeRoundTripsThroughTheKnownEpoch(t *testing.T) {
	// Chromium counts microseconds from 1601-01-01, not the Unix epoch. Getting
	// this wrong writes an expiry in the wrong century, and the browser drops
	// the cookie as expired.
	if got := chromeTime(time.Unix(0, 0)); got != chromeEpochOffset*1_000_000 {
		t.Errorf("chromeTime(unix 0) = %d, want %d", got, chromeEpochOffset*1_000_000)
	}
	future := time.Now().Add(time.Hour)
	if chromeTime(future) <= chromeTime(time.Now()) {
		t.Error("chromeTime is not monotonic")
	}
}

func TestCookieIdentityDistinguishesPathAndDomain(t *testing.T) {
	// Two cookies can share a name and differ only by domain or path; keying on
	// the name alone would write one's value over the other.
	a := cookieIdentity(".acme.test", "sid", "/")
	for _, other := range []string{
		cookieIdentity("acme.test", "sid", "/"),
		cookieIdentity(".acme.test", "sid", "/admin"),
		cookieIdentity(".acme.test", "other", "/"),
	} {
		if a == other {
			t.Errorf("cookieIdentity collided: %q", a)
		}
	}
	index := plaintextIndex([]Cookie{{Domain: ".acme.test", Name: "sid", Path: "/", Value: "v"}})
	if index[a] != "v" {
		t.Errorf("plaintextIndex = %v, want the value under %q", index, a)
	}
}

func TestTableColumnsReportsWhatExists(t *testing.T) {
	// The rewrites name columns conditionally because the cookies table's
	// shape changes between Chromium milestones.
	path := filepath.Join(t.TempDir(), "Cookies")
	writeCookieDB(t, path, nil)
	db, err := sql.Open(sqliteshim.ShimName, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	cols, err := tableColumns(db, "cookies")
	if err != nil {
		t.Fatalf("tableColumns: %v", err)
	}
	for _, want := range []string{"host_key", "encrypted_value", "is_persistent", "expires_utc"} {
		if !cols[want] {
			t.Errorf("column %q not reported", want)
		}
	}
	if cols["no_such_column"] {
		t.Error("a column that does not exist was reported")
	}
}

func TestRenderPlaywrightInitRestoresOnlyItsOwnOrigin(t *testing.T) {
	origins := []Origin{
		{Origin: "https://acme.test", SessionStorage: []StorageItem{{Name: "tok", Value: "abc"}}},
		{Origin: "https://skip.test", LocalStorage: []StorageItem{{Name: "x", Value: "y"}}},
		{Origin: "https://part.test", Partitioned: true, SessionStorage: []StorageItem{{Name: "no", Value: "no"}}},
	}
	var buf strings.Builder
	if err := Render(&buf, nil, FormatPlaywrightInit, RenderOptions{Origins: origins}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "window.location.origin") {
		t.Error("the script must key its data by origin, or it writes one site's state into another")
	}
	if !strings.Contains(out, `"https://acme.test"`) || !strings.Contains(out, `"tok"`) {
		t.Errorf("the session entry is missing:\n%s", out)
	}
	// An origin with no sessionStorage has nothing to restore, and a
	// partitioned one must not be restored as first-party.
	if strings.Contains(out, "skip.test") || strings.Contains(out, "part.test") {
		t.Errorf("the script carried an origin it should not:\n%s", out)
	}
	if !strings.Contains(out, "addInitScript") {
		t.Error("the script should say how to use it")
	}
	if n := SessionStorageItems(origins); n != 1 {
		t.Errorf("SessionStorageItems = %d, want 1", n)
	}
}

func TestOriginFromIndexedDBDir(t *testing.T) {
	cases := map[string]string{
		"https_github.com_0" + indexedDBDirSuffix:     "https://github.com",
		"http_localhost_3000" + indexedDBDirSuffix:    "http://localhost:3000",
		"http_10.99.0.12_8000" + indexedDBDirSuffix:   "http://10.99.0.12:8000",
		"chrome-extension_abc_0" + indexedDBDirSuffix: "chrome-extension://abc",
	}
	for in, want := range cases {
		got, ok := originFromIndexedDBDir(in)
		if !ok || got != want {
			t.Errorf("originFromIndexedDBDir(%q) = (%q, %v), want %q", in, got, ok, want)
		}
	}
	if _, ok := originFromIndexedDBDir("nonsense" + indexedDBDirSuffix); ok {
		t.Error("a name with too few parts should be rejected")
	}
}
