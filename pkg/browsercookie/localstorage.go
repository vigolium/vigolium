package browsercookie

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Local storage lives in a LevelDB store beside the cookie database, in a
// layout Chromium documents in local_storage_impl.cc:
//
//	VERSION                            -> "1"
//	META:https://example.com           -> serialized metadata
//	_https://example.com\x00<key>      -> <value>
//
// Both <key> and <value> carry a leading encoding byte, and the origin is the
// unit of isolation — https://app.example.com and https://example.com are
// separate stores that share nothing, which is why origins are matched as
// host-only names rather than through the cookie domain rules.
const (
	// localStorageDirName is the directory holding the LevelDB store, relative
	// to the profile directory.
	localStorageDirName = "Local Storage"

	// localStorageKeyPrefix marks a key that holds a stored value.
	localStorageKeyPrefix = "_"
	// localStorageMetaPrefix marks per-origin bookkeeping, not a value.
	localStorageMetaPrefix = "META:"

	// encodingUTF16 and encodingLatin1 are the leading byte of an encoded key
	// or value.
	encodingUTF16  = 0x00
	encodingLatin1 = 0x01
)

// Limits on what a single read will pull into memory. The web platform caps
// local storage at around 5 MiB per origin, but a long-lived profile holds
// hundreds of origins, and a profile directory is not a trusted input just
// because it sits in the user's home.
const (
	localStorageMaxValueBytes  = 8 << 20   // 8 MiB per entry
	localStorageMaxTotalBytes  = 256 << 20 // 256 MiB per store
	localStorageMaxCopyBytes   = 512 << 20 // 512 MiB of files copied
	localStorageMaxCopiedFiles = 4096
)

// StorageItem is one local-storage entry.
type StorageItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Origin is one web origin's local storage, in the shape Playwright's
// storageState expects.
type Origin struct {
	// Origin is the origin ("https://app.example.com"), which is the unit
	// local storage is isolated by.
	Origin       string        `json:"origin"`
	LocalStorage []StorageItem `json:"local_storage"`
	// SessionStorage is the origin's sessionStorage, merged across the tabs
	// that held it. Absent unless Query.WithStorage asked for it.
	SessionStorage []StorageItem `json:"session_storage,omitempty"`
	// SessionNamespaces is how many tabs' sessionStorage was merged into
	// SessionStorage, so the merge is visible rather than implied.
	SessionNamespaces int `json:"session_namespaces,omitempty"`

	// Partitioned reports that this is third-party storage keyed to a
	// top-level site: what the origin sees only while embedded in
	// TopLevelSite, not its own first-party store.
	//
	// It is reported rather than silently merged because a quarter of the
	// origins in a real profile are partitioned, and a storageState has no way
	// to express the partition — restoring one as a plain origin writes
	// another site's view of this origin into its first-party bucket.
	Partitioned  bool   `json:"partitioned,omitempty"`
	TopLevelSite string `json:"top_level_site,omitempty"`

	Browser      string `json:"browser"`
	Profile      string `json:"profile,omitempty"`
	ProfileLabel string `json:"profile_label,omitempty"`
}

// ItemCount is how many local and session storage entries the origin holds.
func (o Origin) ItemCount() int {
	return len(o.LocalStorage) + len(o.SessionStorage)
}

// isNetworkLayout reports whether a Chromium cookie store uses the Chrome 96+
// layout, <profile>/Network/Cookies, rather than the legacy <profile>/Cookies.
func isNetworkLayout(cookieFile string) bool {
	return strings.EqualFold(filepath.Base(filepath.Dir(cookieFile)), "Network")
}

// profileDirOf returns the profile directory holding a Chromium cookie store.
//
// Derived from the cookie store's own path so an explicit --user-data-dir
// reaches that profile's storage without a second flag.
func profileDirOf(cookieFile string) string {
	dir := filepath.Dir(cookieFile)
	if isNetworkLayout(cookieFile) {
		dir = filepath.Dir(dir)
	}
	return dir
}

// localStorageLevelDBPath returns where local storage keeps its LevelDB files
// inside a profile: nested under a `leveldb` subdirectory.
//
// Each store owns its own path because the two layouts differ — session storage
// puts its .ldb files directly in `Session Storage`, with no subdirectory — and
// one function keyed on a directory name only let the two be mismatched.
// Assuming the wrong layout finds nothing and reports it as "this origin has no
// storage".
func localStorageLevelDBPath(profile string) string {
	return filepath.Join(profile, localStorageDirName, "leveldb")
}

// storageDirOf returns where a storage system keeps its LevelDB files inside a
// profile directory, and whether that directory exists. layout is the store's
// own path function (localStorageLevelDBPath, sessionStorageLevelDBPath), so
// the existence check is written once for the readers and the clone alike.
func storageDirOf(profile string, layout func(profile string) string) (string, bool) {
	path := layout(profile)
	st, err := os.Stat(path)
	return path, err == nil && st.IsDir()
}

// readLocalStorage reads the local storage of the origins matcher accepts.
//
// The store is copied before it is opened. A running browser holds LevelDB's
// LOCK file, so opening the original fails outright; and LevelDB opens are
// read-write by nature — it replays the write-ahead log to reach a consistent
// state. Doing that to the copy means a read can never alter the profile the
// user is still browsing with.
func readLocalStorage(ctx context.Context, store StoreInfo, matcher *Matcher) ([]Origin, error) {
	dir, ok := storageDirOf(profileDirOf(store.File), localStorageLevelDBPath)
	if !ok {
		return nil, nil
	}

	db, release, err := openStagedLevelDB(dir, localStorageDirName)
	if err != nil {
		// A store that cannot be recovered is reported, not fatal: the cookies
		// are the primary result and are already read by now.
		return nil, err
	}
	defer release()

	byOrigin := map[string][]StorageItem{}
	total := 0
	// Memo for the per-origin decision in the loop: keys arrive grouped by
	// origin, so this collapses N rows of work into N origins.
	var (
		lastKey     string
		lastInScope bool
	)

	iter := db.NewIterator(util.BytesPrefix([]byte(localStorageKeyPrefix)), nil)
	defer iter.Release()
	for iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		storageKey, nameBytes, ok := splitLocalStorageKey(iter.Key())
		if !ok {
			continue
		}
		// Origin first, name second. The decision is per ORIGIN but the loop is
		// per row, and LevelDB returns keys sorted, so one lookup covers every
		// entry of that origin. Decoding the name first would pay a
		// Latin-1/UTF-16 decode for every row of every origin in the profile —
		// ~1700 origins' worth of discarded work for one requested domain.
		if storageKey != lastKey {
			lastKey, lastInScope = storageKey, originInScope(storageKey, matcher)
		}
		if !lastInScope {
			continue
		}
		name := decodeDOMStorageString(nameBytes)
		if name == "" {
			continue
		}
		raw := iter.Value()
		if len(raw) > localStorageMaxValueBytes {
			continue
		}
		total += len(raw)
		if total > localStorageMaxTotalBytes {
			return nil, fmt.Errorf("%s exceeds %d bytes; narrow the domain", localStorageDirName, localStorageMaxTotalBytes)
		}
		byOrigin[storageKey] = append(byOrigin[storageKey], StorageItem{
			Name:  name,
			Value: decodeDOMStorageString(raw),
		})
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", localStorageDirName, err)
	}

	// sessionStorage is read from its own store and attached to the origins
	// found here, plus any origin that has session state and no local storage
	// at all — a real case for an app that keeps only a short-lived token.
	session, namespaces, sessionErr := readSessionStorage(ctx, store, matcher)
	if sessionErr != nil {
		return nil, sessionErr
	}
	for origin := range session {
		if _, ok := byOrigin[origin]; !ok {
			byOrigin[origin] = nil
		}
	}

	out := make([]Origin, 0, len(byOrigin))
	for storageKey, items := range byOrigin {
		sort.SliceStable(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		origin, topLevel := splitStorageKey(storageKey)
		entry := Origin{
			Origin:       origin,
			LocalStorage: items,
			Partitioned:  topLevel != "",
			TopLevelSite: topLevel,
			Browser:      store.Browser,
			Profile:      store.Profile,
			ProfileLabel: store.Label,
		}
		// Session state belongs to the unpartitioned origin: the session store
		// keys namespaces by origin alone, with no partition to carry over.
		if !entry.Partitioned {
			entry.SessionStorage = session[origin]
			entry.SessionNamespaces = namespaces[origin]
		}
		out = append(out, entry)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Origin != out[j].Origin {
			return out[i].Origin < out[j].Origin
		}
		return out[i].TopLevelSite < out[j].TopLevelSite
	})
	return out, nil
}

// openStagedLevelDB stages a browser LevelDB store in a scratch directory and
// opens the copy, returning a release function that closes it and removes the
// staging directory.
//
// Both storage readers need the identical five steps, and both for the same two
// reasons: a running browser holds LevelDB's LOCK file, so the original cannot
// be opened at all; and a LevelDB open replays the write-ahead log, so opening
// the original would mean writing to a profile the user is still browsing with.
//
// The staging directory comes from internal/scratch rather than os.MkdirTemp so
// `vigolium kit tmp-clean` can find it. scratch sweeps its own root; a directory
// allocated outside it is litter nothing in this tool can collect, and a staged
// copy runs to localStorageMaxCopyBytes.
func openStagedLevelDB(dir, label string) (*leveldb.DB, func(), error) {
	tmp, err := scratch.MkdirTemp("vigolium-browserstorage-")
	if err != nil {
		return nil, nil, fmt.Errorf("staging %s: %w", label, err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	if err := copyLevelDBDir(dir, tmp); err != nil {
		cleanup()
		return nil, nil, err
	}
	db, err := leveldb.OpenFile(tmp, &opt.Options{})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("opening %s: %w", label, err)
	}
	return db, func() {
		_ = db.Close()
		cleanup()
	}, nil
}

// parseLocalStorageKey splits a value key into its origin and entry name.
//
// The layout is `_<origin>\x00<encoded name>`: the NUL is the separator, and
// what follows carries its own encoding byte.
func splitLocalStorageKey(key []byte) (storageKey string, nameBytes []byte, ok bool) {
	if len(key) < 2 || key[0] != localStorageKeyPrefix[0] {
		return "", nil, false
	}
	body := key[1:]
	sep := bytes.IndexByte(body, 0x00)
	if sep <= 0 || sep == len(body)-1 {
		return "", nil, false
	}
	return string(body[:sep]), body[sep+1:], true
}

// parseLocalStorageKey splits a value key into its storage key and decoded
// entry name. In a loop prefer splitLocalStorageKey: this decodes the name
// whether or not the caller keeps the row.
func parseLocalStorageKey(key []byte) (storageKey, name string, ok bool) {
	storageKey, nameBytes, ok := splitLocalStorageKey(key)
	if !ok {
		return "", "", false
	}
	if name = decodeDOMStorageString(nameBytes); name == "" {
		return "", "", false
	}
	return storageKey, name, true
}

// decodeDOMStorageString decodes the encoding Chromium uses for DOM storage
// keys and values: a leading byte selects UTF-16 (little endian) or Latin-1.
//
// The fallback matters as much as the two documented cases. A string that
// carries neither marker — a store written by a build whose encoding has moved
// on, or a key this reader has mis-split — is returned as its own bytes when
// they are valid UTF-8, so a readable value is never discarded over a byte
// nobody recognized.
func decodeDOMStorageString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	switch b[0] {
	case encodingLatin1:
		return decodeLatin1(b[1:])
	case encodingUTF16:
		return decodeUTF16LE(b[1:])
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return decodeLatin1(b)
}

// decodeLatin1 widens each byte to its own code point.
//
// ASCII takes a fast path, which is the overwhelming majority of what carries
// the Latin-1 tag: every byte is already its own UTF-8 encoding, so the string
// conversion is the whole transform. The builder is needed only once a byte
// above 0x7f appears — which is also why its hint is 2*len rather than len,
// since each of those becomes two UTF-8 bytes.
func decodeLatin1(b []byte) string {
	for i, c := range b {
		if c > 0x7f {
			var sb strings.Builder
			sb.Grow(2 * len(b))
			sb.Write(b[:i])
			for _, c := range b[i:] {
				sb.WriteRune(rune(c))
			}
			return sb.String()
		}
	}
	return string(b)
}

// decodeUTF16LE decodes little-endian UTF-16, which is how Chromium stores any
// string that does not fit in Latin-1.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1] // a trailing odd byte cannot start a code unit
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(units))
}

// splitStorageKey separates a serialized Chromium StorageKey into the origin
// and, for third-party partitioned storage, the top-level site it is keyed to.
//
// Chromium serializes a partitioned key as `<origin>/^0<top-level site>`, with
// other `^N` markers for nonces and ancestor-chain bits. Everything from the
// first `/^` on is partition metadata, not part of the origin.
func splitStorageKey(storageKey string) (origin, topLevelSite string) {
	i := strings.Index(storageKey, "/^")
	if i < 0 {
		return storageKey, ""
	}
	origin = storageKey[:i]
	rest := storageKey[i+2:]
	// Drop the single-character marker digit ("0", "1", …) that follows "^".
	if len(rest) > 0 {
		rest = rest[1:]
	}
	if rest == "" {
		// A marker with no site (a nonce partition): still partitioned, but
		// there is no site to name. Reported as partitioned via a placeholder
		// so it cannot be mistaken for first-party storage.
		return origin, "(opaque)"
	}
	return origin, rest
}

// originHost extracts the hostname from an origin, dropping the scheme and any
// port. An origin with no host — file://, an opaque origin, or a bare hostname
// that is not an origin at all — yields "".
func originHost(origin string) string {
	return httpmsg.HostnameFromURL(origin)
}

// copyLevelDBDir stages a LevelDB store in dst so it can be opened without
// touching the browser's own files.
//
// LOCK is skipped deliberately: it is the file a running browser holds, and
// copying it would reproduce the contention this copy exists to avoid.
func copyLevelDBDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", localStorageDirName, err)
	}
	if len(entries) > localStorageMaxCopiedFiles {
		return fmt.Errorf("%s holds %d files, more than the %d this reader will stage", localStorageDirName, len(entries), localStorageMaxCopiedFiles)
	}
	var copied int64
	for _, e := range entries {
		if e.IsDir() || e.Name() == "LOCK" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		copied += info.Size()
		if copied > localStorageMaxCopyBytes {
			return fmt.Errorf("%s exceeds %d bytes", localStorageDirName, localStorageMaxCopyBytes)
		}
		if err := copyFile(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// copyFile copies one regular file, owner-readable only: a staged copy of a
// browser profile holds the same secrets the original does.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("staging %s: %w", filepath.Base(src), err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("staging %s: %w", filepath.Base(src), err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("staging %s: %w", filepath.Base(src), err)
	}
	return out.Close()
}
