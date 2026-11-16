package browsercookie

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/uptrace/bun/driver/sqliteshim"
)

// A profile clone is the answer to the storage this package cannot parse.
//
// IndexedDB values are Blink structured-clone blobs; Cache Storage is the disk
// cache format; a service worker's registration is a third store again. Each
// would be its own parser against an unspecified, versioned, engine-internal
// encoding — and a session kept in any of them (Firebase Auth and several SPA
// auth libraries keep theirs in IndexedDB) makes a storageState that restores
// the cookies perfectly and still lands on a login page.
//
// Handing the browser its own files sidesteps all of it. A cloned profile
// opened with Playwright's launchPersistentContext carries cookies, local and
// session storage, IndexedDB, service workers and Cache Storage, because it IS
// the profile — no format is interpreted, so no format can be misread.
//
// The clone is SCOPED, and that is not a nicety. A whole Chrome profile on a
// working machine runs to hundreds of megabytes and holds every site the
// operator is signed into; copying it to hand over one app's session would
// export every other login with it. So each store is pruned to the requested
// origins: cookie rows deleted, storage keys deleted, and only the matching
// per-origin IndexedDB directories copied at all.
const (
	// cloneProfileDir is the profile directory name inside the clone.
	// Playwright's launchPersistentContext passes the clone as
	// --user-data-dir, and Chromium then opens the "Default" profile within
	// it, so the source profile lands under that name whatever it was called.
	cloneProfileDir = "Default"

	// cloneReadmeName is the instruction file written beside the clone.
	cloneReadmeName = "VIGOLIUM-README.md"
)

// CloneResult reports what a profile clone contains.
type CloneResult struct {
	// Dir is the user-data directory to pass to launchPersistentContext.
	Dir string `json:"dir"`
	// Origins are the origins the clone was scoped to.
	Origins []string `json:"origins"`
	// Cookies is how many cookie rows survived pruning.
	Cookies int `json:"cookies"`
	// LocalStorageKeys and SessionStorageKeys are how many storage keys
	// survived pruning.
	LocalStorageKeys   int `json:"local_storage_keys"`
	SessionStorageKeys int `json:"session_storage_keys"`
	// IndexedDBOrigins is how many per-origin IndexedDB stores were copied —
	// the whole point of cloning rather than exporting.
	IndexedDBOrigins int `json:"indexeddb_origins"`
	// SessionCookiesMadePersistent counts the session cookies the clone had to
	// give an expiry so the browser would not discard them on startup.
	SessionCookiesMadePersistent int `json:"session_cookies_made_persistent"`
	// Bytes is the clone's size on disk.
	Bytes int64 `json:"bytes"`
	// Warnings are caveats about what the clone can and cannot do.
	Warnings []string `json:"warnings"`
}

// CloneProfile builds a scoped copy of one browser profile at dir.
//
// The source store must be a Chromium-family profile: the clone's value is
// that Chromium can open it, which a Firefox or Safari store cannot provide.
//
// The clone is built in a sibling staging directory (mode 0700, a dot-name
// beside dir) and renamed onto dir only once it is complete and pruned. Every
// failure — a store that will not prune, a full disk, an interrupt that
// cancels ctx — removes the staging directory, so what is left at dir is the
// finished clone or nothing. Built in place, a failed clone left every site's
// unpruned cookies and storage at the operator's path, under a name that
// invited pointing a browser at it.
func CloneProfile(ctx context.Context, store StoreInfo, matcher *Matcher, cookies []Cookie, dir string) (res CloneResult, err error) {
	res = CloneResult{Dir: dir, Origins: matcher.Targets(), Warnings: []string{}}
	if store.Family != FamilyChromium {
		return res, SelectorError{Err: fmt.Errorf("a profile clone needs a Chromium-family profile; %s is %s", store.Describe(), store.Family)}
	}
	if store.AppBound {
		return res, fmt.Errorf("%s is App-Bound encrypted: a clone would copy cookies no process can decrypt", store.Describe())
	}

	replaceEmpty, err := checkCloneDestination(dir)
	if err != nil {
		return res, err
	}
	parent := filepath.Dir(filepath.Clean(dir))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return res, SelectorError{Err: fmt.Errorf("%s: %w", parent, err)}
	}
	// MkdirTemp creates the directory 0700 (os.MkdirTemp's documented mode).
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(filepath.Clean(dir))+".vigolium-clone-")
	if err != nil {
		return res, fmt.Errorf("creating the clone's staging directory: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := buildClone(ctx, store, matcher, cookies, staging, &res); err != nil {
		return res, err
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if replaceEmpty {
		// An empty directory is replaced rather than merged into; the check
		// above saw it empty, and os.Remove refuses one that no longer is.
		if err := os.Remove(dir); err != nil {
			return res, fmt.Errorf("replacing the empty %s: %w", dir, err)
		}
	}
	if err := os.Rename(staging, dir); err != nil {
		return res, fmt.Errorf("moving the clone into %s: %w", dir, err)
	}
	return res, nil
}

// buildClone writes the scoped clone into dir (the staging directory) and
// fills in res. res.Dir stays the final path: the README names where the
// clone will be, not where it was built.
func buildClone(ctx context.Context, store StoreInfo, matcher *Matcher, cookies []Cookie, dir string, res *CloneResult) error {
	profileDst := filepath.Join(dir, cloneProfileDir)
	if err := os.MkdirAll(profileDst, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", profileDst, err)
	}
	profileSrc := profileDirOf(store.File)

	// Local State is REBUILT rather than copied, carrying only the encryption
	// key when the platform keeps it there (Windows DPAPI; macOS and Linux use
	// the OS keyring and need nothing from this file). The original also holds
	// profile.info_cache — the operator's profile names and signed-in account
	// addresses — which the clone has no use for and no business carrying.
	if err := writeScopedLocalState(store.Root, dir); err != nil {
		return err
	}
	// Preferences is deliberately NOT copied: it holds per-site content
	// settings and permissions for every site the operator has visited, which
	// no other prune would remove. Chromium writes a fresh one.

	kept, rewritten, err := cloneCookies(store, profileDst, matcher, cookies)
	if err != nil {
		return err
	}
	res.Cookies = kept
	res.SessionCookiesMadePersistent = rewritten
	if err := ctx.Err(); err != nil {
		return err
	}

	res.LocalStorageKeys, err = cloneStorageDir(ctx, profileSrc, profileDst, localStorageClone, matcher)
	if err != nil {
		return err
	}
	res.SessionStorageKeys, err = cloneStorageDir(ctx, profileSrc, profileDst, sessionStorageClone, matcher)
	if err != nil {
		return err
	}

	res.IndexedDBOrigins, err = cloneIndexedDB(ctx, profileSrc, profileDst, matcher)
	if err != nil {
		return err
	}

	// Everything in the clone is a credential, including the files LevelDB
	// created for itself while it was being pruned (goleveldb writes its
	// CURRENT and LOCK world-readable). The directory mode is the real gate,
	// but a session should not depend on one bit.
	size, err := restrictTree(dir)
	if err != nil {
		return err
	}
	res.Bytes = size
	res.Warnings = cloneWarnings(*res)

	if err := os.WriteFile(filepath.Join(dir, cloneReadmeName), []byte(cloneReadme(*res, store)), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", cloneReadmeName, err)
	}
	return nil
}

// writeScopedLocalState writes the clone's Local State with the encryption key
// and nothing else.
//
// On Windows the cookie key is a DPAPI blob in this file, so a clone without it
// holds cookies that cannot be decrypted. Everywhere else the key comes from
// the OS keyring and the file is pure bookkeeping, so the clone gets none of it.
func writeScopedLocalState(root, dir string) error {
	if root == "" {
		return nil
	}
	state := readLocalState(root)
	if state.OSCrypt.EncryptedKey == "" {
		return nil
	}
	doc := map[string]any{
		"os_crypt": map[string]string{"encrypted_key": state.OSCrypt.EncryptedKey},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("writing Local State: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Local State"), data, 0o600); err != nil {
		return fmt.Errorf("writing Local State: %w", err)
	}
	return nil
}

// restrictTree makes every file in the clone owner-only and returns the clone's
// total size.
//
// The size comes from the same walk rather than a second dirSize pass: with a
// scoped IndexedDB origin copied in, the clone runs to hundreds of files and
// there is no reason to traverse it twice in a row.
func restrictTree(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(path, 0o700)
		}
		if info, ierr := d.Info(); ierr == nil {
			total += info.Size()
		}
		return os.Chmod(path, 0o600)
	})
	return total, err
}

// cloneWarnings states what the clone cannot do, in the clone itself.
func cloneWarnings(res CloneResult) []string {
	out := []string{
		"This clone is a live session for " + strings.Join(res.Origins, ", ") + ". Treat the directory as a credential.",
		"Cookie values were rewritten as plaintext in the cloned store so a launched browser can read them without this machine's keyring key. The directory is readable session state, not an encrypted copy.",
		"Service Worker and Cache Storage are not copied: they are caches rather than session state, and they are the largest thing in a profile.",
		"Preferences are not copied either — they carry per-site settings for every site visited — so the browser will open this profile with default settings.",
	}
	if res.SessionStorageKeys > 0 {
		// Verified by opening a clone: the browser reported 0 sessionStorage
		// keys. It is per-tab state, and a launch starts new namespaces rather
		// than adopting the ones on disk, so the copy sits there unused unless
		// the browser is told to restore the previous session.
		out = append(out, fmt.Sprintf("The %d sessionStorage key(s) in this clone will NOT be restored by a normal launch — sessionStorage is per-tab and the browser starts fresh namespaces. Use `--as playwright-init` and context.addInitScript to put them back.",
			res.SessionStorageKeys))
	}
	if res.SessionCookiesMadePersistent > 0 {
		out = append(out, fmt.Sprintf("%d session cookie(s) were given a %s expiry, because a browser discards cookies with no expiry when it starts.",
			res.SessionCookiesMadePersistent, cloneSessionCookieLife))
	}
	if res.IndexedDBOrigins == 0 {
		out = append(out, "No IndexedDB was found for these origins, so a plain --as playwright storageState would have carried the same session.")
	}
	return out
}

// checkCloneDestination validates the clone's destination without creating
// it, and reports whether an existing empty directory is there to replace.
//
// An existing non-empty directory is refused rather than merged into: a clone
// half of which is someone else's profile is worse than no clone, and this is
// the one output of this package a caller is invited to point a browser at.
func checkCloneDestination(dir string) (replaceEmpty bool, err error) {
	st, err := os.Stat(dir)
	switch {
	case os.IsNotExist(err):
		return false, nil
	case err != nil:
		return false, SelectorError{Err: fmt.Errorf("%s: %w", dir, err)}
	case !st.IsDir():
		return false, SelectorError{Err: fmt.Errorf("%s is a file; a profile clone needs a directory", dir)}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, SelectorError{Err: fmt.Errorf("%s: %w", dir, err)}
	}
	if len(entries) > 0 {
		return false, SelectorError{Err: fmt.Errorf("%s is not empty; a profile clone needs an empty or new directory", dir)}
	}
	return true, nil
}

// cloneCookies copies the cookie database, deletes every row outside scope, and
// rewrites the rows that survive so a launched browser can actually use them.
//
// Pruning is a DELETE on the copy, and the rewrites are UPDATEs, rather than a
// filtered insert: the cookies table's columns change between Chromium
// milestones, and a SELECT-and-INSERT clone would have to name them all and
// would silently drop whichever ones this code had not heard of.
//
// Two rewrites, and the clone is useless without either. Both were found by
// opening a clone and watching the browser throw its cookies away:
//
//   - Values are written as PLAINTEXT, clearing encrypted_value. The copied
//     values are sealed with this browser brand's OS keyring key, and an
//     automation launch does not have it: Playwright starts browsers with
//     --use-mock-keychain, so Chrome derives a different key, fails to decrypt
//     every row, and DELETES them. A clone opened once went from 16 cookies to
//     2. Chromium still honours a plaintext `value` when encrypted_value is
//     empty, which also makes the clone brand-independent — a Chrome profile
//     opens in Chromium and vice versa.
//   - Session cookies are given an expiry. A cookie with no expiry is
//     discarded when the browser starts, which is correct for a browser and
//     fatal here: it is where GitHub, and most apps, keep the actual session.
//     The expiry is deliberately short — a cookie that was never meant to
//     outlive its session should not outlive the agent's run by much.
func cloneCookies(store StoreInfo, profileDst string, matcher *Matcher, cookies []Cookie) (kept, rewritten int, err error) {
	// Keep the store at the same place within the profile, so the clone's
	// layout matches what the browser that wrote it expects.
	rel := "Cookies"
	if isNetworkLayout(store.File) {
		rel = filepath.Join("Network", "Cookies")
	}
	dst := filepath.Join(profileDst, rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return 0, 0, fmt.Errorf("creating %s: %w", filepath.Dir(dst), err)
	}
	if err := copyFile(store.File, dst); err != nil {
		return 0, 0, err
	}
	// A WAL or journal beside the store holds writes the main file does not.
	// Copied so the clone is the same database the browser has, not an older
	// snapshot of it.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := copyFileIfPresent(store.File+suffix, dst+suffix); err != nil {
			return 0, 0, err
		}
	}

	db, err := sql.Open(sqliteshim.ShimName, dst)
	if err != nil {
		return 0, 0, fmt.Errorf("opening the cloned cookie store: %w", err)
	}
	defer func() { _ = db.Close() }()

	plain := plaintextIndex(cookies)
	columns, err := tableColumns(db, "cookies")
	if err != nil {
		return 0, 0, err
	}

	rows, err := db.Query(`SELECT rowid, host_key, name, path FROM cookies`)
	if err != nil {
		return 0, 0, fmt.Errorf("reading the cloned cookie store: %w", err)
	}
	type row struct {
		id    int64
		value string
		known bool
	}
	var (
		drop []int64
		keep []row
	)
	for rows.Next() {
		var (
			id                   int64
			hostKey, name, cpath string
		)
		if err := rows.Scan(&id, &hostKey, &name, &cpath); err != nil {
			_ = rows.Close()
			return 0, 0, fmt.Errorf("reading the cloned cookie store: %w", err)
		}
		if !matcher.Match(hostKey) {
			drop = append(drop, id)
			continue
		}
		value, known := plain[cookieIdentity(hostKey, name, cpath)]
		keep = append(keep, row{id: id, value: value, known: known})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, 0, fmt.Errorf("reading the cloned cookie store: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, 0, fmt.Errorf("pruning the cloned cookie store: %w", err)
	}
	rollback := func(e error) (int, int, error) {
		_ = tx.Rollback()
		return 0, 0, e
	}

	// Prepared once and reused. A scoped clone deletes nearly every row of a
	// profile's cookie store — thousands of them — and tx.Exec parses and
	// finalizes a fresh statement per call.
	del, err := tx.Prepare(`DELETE FROM cookies WHERE rowid = ?`)
	if err != nil {
		return rollback(fmt.Errorf("pruning the cloned cookie store: %w", err))
	}
	defer func() { _ = del.Close() }()

	// The SET clause varies only by whether this Chromium version has the
	// column, so it is chosen once rather than duplicating the loop.
	set := `SET value = ?`
	if columns["encrypted_value"] {
		set = `SET value = ?, encrypted_value = x''`
	}
	upd, err := tx.Prepare(`UPDATE cookies ` + set + ` WHERE rowid = ?`)
	if err != nil {
		return rollback(fmt.Errorf("rewriting the cloned cookie store: %w", err))
	}
	defer func() { _ = upd.Close() }()

	for _, id := range drop {
		if _, err := del.Exec(id); err != nil {
			return rollback(fmt.Errorf("pruning the cloned cookie store: %w", err))
		}
	}
	for _, r := range keep {
		// A row whose plaintext this read never saw cannot be rewritten, and
		// leaving it encrypted means the browser deletes it on open. Dropping
		// it here instead keeps the clone's own count honest.
		if !r.known {
			if _, err := del.Exec(r.id); err != nil {
				return rollback(fmt.Errorf("pruning the cloned cookie store: %w", err))
			}
			continue
		}
		if _, err := upd.Exec(r.value, r.id); err != nil {
			return rollback(fmt.Errorf("rewriting the cloned cookie store: %w", err))
		}
		kept++
	}

	if columns["is_persistent"] && columns["expires_utc"] {
		expiry := chromeTime(time.Now().Add(cloneSessionCookieLife))
		persist := `SET is_persistent = 1, expires_utc = ?`
		if columns["has_expires"] {
			persist = `SET is_persistent = 1, has_expires = 1, expires_utc = ?`
		}
		result, err := tx.Exec(`UPDATE cookies `+persist+` WHERE is_persistent = 0`, expiry)
		if err != nil {
			return rollback(fmt.Errorf("rewriting the cloned cookie store: %w", err))
		}
		if n, err := result.RowsAffected(); err == nil {
			rewritten = int(n)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("pruning the cloned cookie store: %w", err)
	}
	// VACUUM so the deleted rows' bytes leave the file rather than lingering
	// in free pages that still hold other sites' cookies.
	if _, err := db.Exec(`VACUUM`); err != nil {
		return kept, rewritten, fmt.Errorf("compacting the cloned cookie store: %w", err)
	}
	return kept, rewritten, nil
}

// cloneSessionCookieLife is how long a session cookie lives in a clone. Short
// on purpose: it was never meant to outlive the browser session it came from.
const cloneSessionCookieLife = 12 * time.Hour

// chromeEpochOffset is the seconds between 1601-01-01 and the Unix epoch.
// Chromium stores cookie times as microseconds since 1601.
const chromeEpochOffset = 11644473600

// chromeTime converts a time to Chromium's cookie timestamp.
func chromeTime(t time.Time) int64 {
	return (t.Unix() + chromeEpochOffset) * 1_000_000
}

// cookieIdentity keys a cookie by what the store uses to identify one.
func cookieIdentity(domain, name, path string) string {
	return domain + "\x00" + name + "\x00" + path
}

// plaintextIndex maps each already-decrypted cookie to its value, so the clone
// can write plaintext the launched browser will accept.
func plaintextIndex(cookies []Cookie) map[string]string {
	out := make(map[string]string, len(cookies))
	for _, c := range cookies {
		out[cookieIdentity(c.Domain, c.Name, c.Path)] = c.Value
	}
	return out
}

// tableColumns returns the column names of a table, so an UPDATE only names
// columns this Chromium version actually has.
func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, fmt.Errorf("inspecting %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("inspecting %s: %w", table, err)
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inspecting %s: %w", table, err)
	}
	return out, nil
}

// storageClone describes one storage system for the clone: where its LevelDB
// files live and how to prune them.
//
// One value per store, defined beside that store's reader, because the name,
// the path layout and the prune pass belong together — passed as separate
// arguments, `localStorageDirName` with `pruneSessionStorage` was a call that
// compiled. A third store adds a value here rather than an argument at every
// call site.
type storageClone struct {
	name  string
	path  func(profile string) string
	prune func(*leveldb.DB, *Matcher) (int, error)
}

var (
	localStorageClone = storageClone{
		name: localStorageDirName, path: localStorageLevelDBPath, prune: pruneLocalStorage,
	}
	sessionStorageClone = storageClone{
		name: sessionStorageDirName, path: sessionStorageLevelDBPath, prune: pruneSessionStorage,
	}
)

// cloneStorageDir copies one LevelDB storage directory and prunes it to scope.
func cloneStorageDir(ctx context.Context, profileSrc, profileDst string, store storageClone, matcher *Matcher) (int, error) {
	name := store.name
	src, ok := storageDirOf(profileSrc, store.path)
	if !ok {
		return 0, nil
	}
	dst := store.path(profileDst)
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return 0, fmt.Errorf("creating %s: %w", dst, err)
	}
	if err := copyLevelDBDir(src, dst); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	db, err := leveldb.OpenFile(dst, nil)
	if err != nil {
		return 0, fmt.Errorf("opening the cloned %s: %w", name, err)
	}
	kept, pruneErr := store.prune(db, matcher)
	if pruneErr == nil {
		// Compact, or the prune is a lie. A LevelDB delete writes a tombstone;
		// the key stops being readable but its bytes stay in the SST files
		// until a compaction rewrites them. Without this the clone still
		// physically contains every other site's storage — which is exactly
		// what scoping the clone was for, and what its README promises was
		// removed.
		pruneErr = db.CompactRange(util.Range{})
	}
	if cerr := db.Close(); cerr != nil && pruneErr == nil {
		pruneErr = cerr
	}
	if pruneErr != nil {
		return 0, fmt.Errorf("pruning the cloned %s: %w", name, pruneErr)
	}
	return kept, nil
}

// pruneLocalStorage deletes every local-storage key that is not provably
// in scope.
//
// Default-deny: a key survives only when it is VERSION (bookkeeping the
// browser needs) or belongs to an in-scope origin — a value row
// (_<origin>\x00<key>) or a per-origin metadata row (META:<origin>,
// METAACCESS:<origin>). Everything else is deleted, including a row shape
// this code has not seen: an allow-list of known out-of-scope shapes kept
// whatever it did not recognise, which is how every other site's METAACCESS:
// rows (an access log of each origin) survived into the clone.
//
// The batch is flushed as it fills rather than accumulating the whole profile's
// out-of-scope keys: unlike the read paths this has no byte budget, and a
// working profile holds every key of some seventeen hundred other origins, each
// copied into the batch.
func pruneLocalStorage(db *leveldb.DB, matcher *Matcher) (int, error) {
	flusher := newBatchFlusher(db)
	kept := 0
	var (
		lastKey     string
		lastInScope bool
	)
	iter := db.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		keep := false
		switch {
		case string(key) == "VERSION":
			keep = true
		case bytes.HasPrefix(key, []byte(localStorageKeyPrefix)):
			// Key only: the entry name is decoded nowhere here, so splitting
			// without decoding saves a decode per row of the whole store.
			if storageKey, _, ok := splitLocalStorageKey(key); ok {
				if storageKey != lastKey {
					lastKey, lastInScope = storageKey, originInScope(storageKey, matcher)
				}
				if lastInScope {
					kept++
					keep = true
				}
			}
		default:
			if origin, ok := localStorageMetaOrigin(key); ok {
				keep = originInScope(origin, matcher)
			}
		}
		if keep {
			continue
		}
		if err := flusher.delete(key); err != nil {
			iter.Release()
			return 0, err
		}
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return 0, err
	}
	return kept, flusher.done()
}

// localStorageMetaPrefixes are the per-origin bookkeeping rows a scoped clone
// keeps for an in-scope origin: META: (size and last-modified) and
// METAACCESS: (last access).
var localStorageMetaPrefixes = []string{localStorageMetaPrefix, "METAACCESS:"}

// localStorageMetaOrigin returns the storage key a per-origin metadata row
// names.
func localStorageMetaOrigin(key []byte) (string, bool) {
	for _, p := range localStorageMetaPrefixes {
		if bytes.HasPrefix(key, []byte(p)) {
			return string(key[len(p):]), true
		}
	}
	return "", false
}

// batchFlusherMaxKeys bounds a prune's in-flight delete batch.
const batchFlusherMaxKeys = 10_000

// batchFlusher accumulates LevelDB deletes and writes them in bounded chunks.
type batchFlusher struct {
	db    *leveldb.DB
	batch *leveldb.Batch
}

func newBatchFlusher(db *leveldb.DB) *batchFlusher {
	return &batchFlusher{db: db, batch: new(leveldb.Batch)}
}

// delete queues a key, writing the batch out once it is large enough. The key
// is copied because the iterator reuses its buffer.
func (f *batchFlusher) delete(key []byte) error {
	f.batch.Delete(append([]byte(nil), key...))
	if f.batch.Len() < batchFlusherMaxKeys {
		return nil
	}
	return f.done()
}

// done writes whatever is queued and resets.
func (f *batchFlusher) done() error {
	if f.batch.Len() == 0 {
		return nil
	}
	if err := f.db.Write(f.batch, nil); err != nil {
		return err
	}
	f.batch.Reset()
	return nil
}

// pruneSessionStorage deletes every session-storage namespace and map outside
// scope.
//
// The two passes are not optional: a map key names only its map id, so which
// maps to keep is known only after the namespaces have been read.
func pruneSessionStorage(db *leveldb.DB, matcher *Matcher) (int, error) {
	flusher := newBatchFlusher(db)
	keepMaps := map[string]bool{}
	nsIter := db.NewIterator(util.BytesPrefix([]byte(sessionNamespacePrefix)), nil)
	for nsIter.Next() {
		origin, ok := parseSessionNamespaceKey(nsIter.Key())
		if ok && originInScope(origin, matcher) {
			keepMaps[strings.TrimSpace(string(nsIter.Value()))] = true
			continue
		}
		if err := flusher.delete(nsIter.Key()); err != nil {
			nsIter.Release()
			return 0, err
		}
	}
	nsIter.Release()
	if err := nsIter.Error(); err != nil {
		return 0, err
	}

	kept := 0
	mapIter := db.NewIterator(util.BytesPrefix([]byte(sessionMapPrefix)), nil)
	for mapIter.Next() {
		mapID, _, ok := parseSessionMapKey(mapIter.Key())
		if ok && keepMaps[mapID] {
			kept++
			continue
		}
		if err := flusher.delete(mapIter.Key()); err != nil {
			mapIter.Release()
			return 0, err
		}
	}
	mapIter.Release()
	if err := mapIter.Error(); err != nil {
		return 0, err
	}
	return kept, flusher.done()
}

// originInScope reports whether a storage key's origin is in scope, ignoring
// any partition suffix.
func originInScope(storageKey string, matcher *Matcher) bool {
	origin, _ := splitStorageKey(storageKey)
	host := originHost(origin)
	return host != "" && matcher.Match(host)
}

// cloneIndexedDB copies the per-origin IndexedDB directories in scope.
//
// Nothing is parsed or pruned here: IndexedDB is already partitioned by origin
// in the directory NAME, so selecting directories is the whole of the scoping,
// and the browser reads its own format back.
func cloneIndexedDB(ctx context.Context, profileSrc, profileDst string, matcher *Matcher) (int, error) {
	srcRoot := filepath.Join(profileSrc, indexedDBDirName)
	entries, err := os.ReadDir(srcRoot)
	if err != nil {
		return 0, nil // a profile with no IndexedDB is ordinary
	}
	copied := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(e.Name(), indexedDBDirSuffix), indexedDBBlobSuffix)
		if base == e.Name() {
			continue // neither a leveldb nor a blob directory
		}
		origin, ok := originFromIndexedDBDir(base + indexedDBDirSuffix)
		if !ok {
			continue
		}
		if !originInScope(origin, matcher) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return copied, err
		}
		if err := copyTree(filepath.Join(srcRoot, e.Name()), filepath.Join(profileDst, indexedDBDirName, e.Name())); err != nil {
			return copied, err
		}
		if strings.HasSuffix(e.Name(), indexedDBDirSuffix) {
			copied++
		}
	}
	return copied, nil
}

// copyTree copies a directory recursively, owner-only.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil // a lock or socket has no place in a copy
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return copyFile(path, target)
	})
}

// copyFileIfPresent copies src to dst when src exists.
func copyFileIfPresent(src, dst string) error {
	if st, err := os.Stat(src); err != nil || !st.Mode().IsRegular() {
		return nil
	}
	return copyFile(src, dst)
}

// cloneReadme is the instruction file written into the clone.
//
// It lives in the clone rather than only in the terminal because the directory
// outlives the command that made it: whoever finds it next needs to know what
// it is, that it is a credential, and how to open it.
func cloneReadme(res CloneResult, store StoreInfo) string {
	var sb strings.Builder
	sb.WriteString("# Browser profile clone\n\n")
	fmt.Fprintf(&sb, "Written by `vigolium kit cookies --as profile` from %s.\n\n", store.Describe())
	fmt.Fprintf(&sb, "Scoped to: %s\n\n", strings.Join(res.Origins, ", "))
	sb.WriteString("## What is here\n\n")
	fmt.Fprintf(&sb, "- %d cookie(s)\n", res.Cookies)
	fmt.Fprintf(&sb, "- %d localStorage key(s), %d sessionStorage key(s)\n", res.LocalStorageKeys, res.SessionStorageKeys)
	fmt.Fprintf(&sb, "- %d origin(s) of IndexedDB\n\n", res.IndexedDBOrigins)
	sb.WriteString("Everything belonging to other sites has been deleted from the copied\n")
	sb.WriteString("stores. Service Worker and Cache Storage were not copied.\n\n")
	sb.WriteString("## Opening it\n\n")
	sb.WriteString("```js\nconst { chromium } = require('playwright');\n\n")
	sb.WriteString("const ctx = await chromium.launchPersistentContext(")
	fmt.Fprintf(&sb, "%q, {\n", res.Dir)
	sb.WriteString("  channel: 'chrome', // or leave out to use Playwright's bundled Chromium\n")
	sb.WriteString("  headless: false,\n")
	sb.WriteString("});\nconst page = await ctx.newPage();\n```\n\n")
	sb.WriteString("Unlike a `storageState`, this carries IndexedDB — which is where some\n")
	sb.WriteString("apps keep the session a cookie export cannot reproduce.\n\n")
	sb.WriteString("## Caveats\n\n")
	for _, w := range res.Warnings {
		fmt.Fprintf(&sb, "- %s\n", w)
	}
	return sb.String()
}

// CloneOriginSummary renders the clone's scope for a one-line report.
func CloneOriginSummary(res CloneResult) string {
	origins := append([]string(nil), res.Origins...)
	sort.Strings(origins)
	return strings.Join(origins, ", ")
}
