package cli

import (
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
)

// --host and --skip-findings on a path source narrow a SQLite→SQLite merge
// (database.MergeOptions.Hosts / SkipFindings). No other importer can honour
// either, so a source of another kind is refused rather than imported whole:
// a driver that asked for one host and received every host's traffic has no
// signal that anything was dropped.

// importPathHosts reads --host as a merge filter: nil when unset, else the one
// pattern. One pattern per import, because the same flag is a single string to
// the bridge listener; a caller wanting several hosts imports once per host,
// which the merge's natural-key dedup makes safe. A comma is refused rather
// than read as a list the bridge path would not read the same way.
func importPathHosts() ([]string, error) {
	h := strings.TrimSpace(importBridgeHost)
	if h == "" {
		return nil, nil
	}
	if strings.Contains(h, ",") {
		return nil, usageErrorf("--host takes one host pattern, got %q; import once per host (re-importing a source is idempotent)", h)
	}
	if database.ParseHostFilter(h).Host == "" {
		return nil, usageErrorf("--host %q names no host", h)
	}
	return []string{h}, nil
}

// importSQLiteOnlyFlags names the set flags that only a SQLite path source
// honours.
func importSQLiteOnlyFlags() []string {
	var flags []string
	if strings.TrimSpace(importBridgeHost) != "" {
		flags = append(flags, "--host")
	}
	if importSkipFindings {
		flags = append(flags, "--skip-findings")
	}
	return flags
}

// refuseSQLiteOnlyImportFlags checks every local source before the import
// opens the database. gs:// sources are checked after their download, in
// importOneSource.
func refuseSQLiteOnlyImportFlags(sources []string) error {
	flags := importSQLiteOnlyFlags()
	if len(flags) == 0 {
		return nil
	}
	for _, src := range sources {
		if strings.HasPrefix(src, "gs://") {
			continue
		}
		if err := checkSQLiteOnlyImportSource(src, src, flags); err != nil {
			return err
		}
	}
	return nil
}

// checkSQLiteOnlyImportSource refuses flags for a local source that is not a
// vigolium SQLite database. A source that cannot be inspected passes: the
// import reports it, as a per-source failure in a multi-source run.
func checkSQLiteOnlyImportSource(localPath, label string, flags []string) error {
	kind, err := dbimport.DetectSourceKind(localPath)
	if err != nil || kind == dbimport.SourceSQLite {
		return nil
	}
	verb, bridge := "applies", ""
	if len(flags) > 1 {
		verb = "apply"
	}
	if slices.Contains(flags, "--host") {
		bridge = " (--host also to a --burp-bridge-url pull)"
	}
	return usageErrorf("%s %s only to a %s source%s; %s is a %s",
		strings.Join(flags, " and "), verb, dbimport.SourceSQLite, bridge, label, kind)
}
