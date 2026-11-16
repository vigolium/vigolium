package browsercookie

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// IndexedDB is stored per origin, in its own LevelDB directory named after the
// origin: `https_github.com_0.indexeddb.leveldb`, with large values spilled to
// a sibling `.blob` directory.
//
// This file does not read those databases, and deliberately so. The keys are a
// packed binary encoding of database, object-store and index ids, and the
// values are Blink's structured-clone serialization — a versioned,
// engine-internal format with no specification outside Chromium's source, whose
// tags change between milestones. A partial parser would be the worst of the
// options: it would return something, and a caller cannot tell a value it
// decoded wrong from a value the app never stored.
//
// What this file does instead is tell the truth about what is there. An origin
// whose session lives in IndexedDB — Firebase Auth and several SPA auth
// libraries do exactly that — produces a storageState that restores cookies
// perfectly and still lands on a login page, with nothing in the output to
// explain it. Reporting the database's presence turns that into a known
// limitation with a documented way around it: the profile clone, which hands
// the browser its own files and needs no parser at all.
const (
	indexedDBDirName    = "IndexedDB"
	indexedDBDirSuffix  = ".indexeddb.leveldb"
	indexedDBBlobSuffix = ".indexeddb.blob"
)

// OriginStore describes a per-origin store this reader can see but not parse.
type OriginStore struct {
	// Origin is the origin the store belongs to.
	Origin string `json:"origin"`
	// Kind names the storage system ("indexeddb").
	Kind string `json:"kind"`
	// Bytes is the store's size on disk, as a proxy for whether it holds
	// anything worth caring about.
	Bytes int64 `json:"bytes"`
	// Path is the directory holding it.
	Path string `json:"path"`
}

// indexedDBStores lists the IndexedDB directories of the origins matcher
// accepts, with their sizes.
func indexedDBStores(cookieFile string, matcher *Matcher) []OriginStore {
	root := filepath.Join(profileDirOf(cookieFile), indexedDBDirName)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []OriginStore
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), indexedDBDirSuffix) {
			continue
		}
		origin, ok := originFromIndexedDBDir(e.Name())
		if !ok {
			continue
		}
		if !originInScope(origin, matcher) {
			continue
		}
		path := filepath.Join(root, e.Name())
		out = append(out, OriginStore{
			Origin: origin,
			Kind:   "indexeddb",
			Bytes:  dirSize(path),
			Path:   path,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Origin < out[j].Origin })
	return out
}

// originFromIndexedDBDir recovers an origin from an IndexedDB directory name.
//
// The name is `<scheme>_<host>_<port>.indexeddb.leveldb`, with port 0 standing
// for the scheme's default. It is parsed back rather than constructed forward:
// building the expected name from an origin means reproducing Chromium's
// escaping rules exactly, while reading the directory that is actually there
// cannot disagree with the profile.
func originFromIndexedDBDir(name string) (string, bool) {
	base := strings.TrimSuffix(name, indexedDBDirSuffix)
	parts := strings.Split(base, "_")
	if len(parts) < 3 {
		return "", false
	}
	scheme := parts[0]
	port := parts[len(parts)-1]
	// A host may itself contain "_", so everything between is the host.
	host := strings.Join(parts[1:len(parts)-1], "_")
	if scheme == "" || host == "" {
		return "", false
	}
	origin := scheme + "://" + host
	if port != "0" && port != "" && isDigits(port) {
		origin += ":" + port
	}
	return origin, true
}

// dirSize totals the regular files under dir. Errors are ignored: the number is
// a hint about significance, not an accounting.
func dirSize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable entry contributes nothing
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}
