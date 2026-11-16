package browsercookie

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/syndtr/goleveldb/leveldb/util"
)

// Session storage is a second LevelDB store beside local storage, with an
// indirection local storage does not have:
//
//	version                                        -> "1"
//	namespace-<tab uuid>-<origin>/                 -> <map id>
//	map-<map id>-<key>                             -> <value>
//
// The indirection is the whole difference: sessionStorage is scoped to a TAB,
// so one origin has as many namespaces as it has open tabs, each with its own
// map. Reading it means resolving namespaces to map ids first, then collecting
// the maps — there is no key that names both an origin and an entry.
const (
	// sessionStorageDirName is the directory holding the LevelDB store,
	// relative to the profile directory.
	sessionStorageDirName = "Session Storage"

	sessionNamespacePrefix = "namespace-"
	sessionMapPrefix       = "map-"
)

// sessionStorageLevelDBPath returns where session storage keeps its LevelDB
// files inside a profile: directly in `Session Storage`, with no `leveldb`
// subdirectory — unlike local storage. See localStorageLevelDBPath.
func sessionStorageLevelDBPath(profile string) string {
	return filepath.Join(profile, sessionStorageDirName)
}

// readSessionStorage reads the sessionStorage of the origins matcher accepts,
// keyed by origin.
//
// Entries from every one of an origin's namespaces are merged, with the
// namespace count reported so the merge is visible. A browser with three GitHub
// tabs holds three independent sessionStorages; nothing in the store says which
// tab a caller means, and the alternative — picking one arbitrarily — drops
// state without saying so.
func readSessionStorage(ctx context.Context, store StoreInfo, matcher *Matcher) (map[string][]StorageItem, map[string]int, error) {
	dir, ok := storageDirOf(profileDirOf(store.File), sessionStorageLevelDBPath)
	if !ok {
		return nil, nil, nil
	}

	db, release, err := openStagedLevelDB(dir, sessionStorageDirName)
	if err != nil {
		return nil, nil, err
	}
	defer release()

	// Pass one: resolve the namespaces of matching origins to their map ids.
	mapOrigin := map[string]string{}
	namespaces := map[string]int{}
	nsIter := db.NewIterator(util.BytesPrefix([]byte(sessionNamespacePrefix)), nil)
	for nsIter.Next() {
		origin, ok := parseSessionNamespaceKey(nsIter.Key())
		if !ok {
			continue
		}
		if !originInScope(origin, matcher) {
			continue
		}
		mapID := strings.TrimSpace(string(nsIter.Value()))
		if mapID == "" {
			continue
		}
		mapOrigin[mapID] = origin
		namespaces[origin]++
	}
	nsIter.Release()
	if err := nsIter.Error(); err != nil {
		return nil, nil, fmt.Errorf("reading %s namespaces: %w", sessionStorageDirName, err)
	}
	if len(mapOrigin) == 0 {
		return nil, nil, nil
	}

	// Pass two: collect the entries of those maps.
	merged := map[string]map[string]string{}
	total := 0
	mapIter := db.NewIterator(util.BytesPrefix([]byte(sessionMapPrefix)), nil)
	defer mapIter.Release()
	for mapIter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		mapID, name, ok := parseSessionMapKey(mapIter.Key())
		if !ok {
			continue
		}
		origin, wanted := mapOrigin[mapID]
		if !wanted {
			continue
		}
		raw := mapIter.Value()
		if len(raw) > localStorageMaxValueBytes {
			continue
		}
		total += len(raw)
		if total > localStorageMaxTotalBytes {
			return nil, nil, fmt.Errorf("%s exceeds %d bytes; narrow the domain", sessionStorageDirName, localStorageMaxTotalBytes)
		}
		if merged[origin] == nil {
			merged[origin] = map[string]string{}
		}
		merged[origin][name] = decodeDOMStorageString(raw)
	}
	if err := mapIter.Error(); err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", sessionStorageDirName, err)
	}

	out := make(map[string][]StorageItem, len(merged))
	for origin, entries := range merged {
		items := make([]StorageItem, 0, len(entries))
		for name, value := range entries {
			items = append(items, StorageItem{Name: name, Value: value})
		}
		sort.SliceStable(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		out[origin] = items
	}
	return out, namespaces, nil
}

// parseSessionNamespaceKey extracts the origin from a namespace key.
//
// The layout is `namespace-<tab uuid>-<origin>`. The uuid separates its fields
// with underscores, so the first `-` after the prefix ends it — which matters,
// because an origin may itself contain `-` (https://demo-sit.example.com).
func parseSessionNamespaceKey(key []byte) (origin string, ok bool) {
	s := string(key)
	if !strings.HasPrefix(s, sessionNamespacePrefix) {
		return "", false
	}
	rest := s[len(sessionNamespacePrefix):]
	i := strings.IndexByte(rest, '-')
	if i < 0 || i == len(rest)-1 {
		return "", false
	}
	origin = strings.TrimSuffix(rest[i+1:], "/")
	if origin == "" {
		return "", false
	}
	return origin, true
}

// parseSessionMapKey splits `map-<map id>-<key>` into its map id and entry
// name.
//
// Only the id's digits are consumed: an entry name routinely contains `-`
// ("grok-main-thread-watch-tab"), so splitting on the last separator, or on
// every one, truncates real keys.
func parseSessionMapKey(key []byte) (mapID, name string, ok bool) {
	s := string(key)
	if !strings.HasPrefix(s, sessionMapPrefix) {
		return "", "", false
	}
	rest := s[len(sessionMapPrefix):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 || end >= len(rest) || rest[end] != '-' {
		return "", "", false
	}
	mapID = rest[:end]
	name = rest[end+1:]
	if name == "" {
		return "", "", false
	}
	return mapID, name, true
}
