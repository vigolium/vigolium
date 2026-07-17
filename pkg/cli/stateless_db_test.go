package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// writeGlobFixture writes a minimal {type,data} JSONL export with one HTTP
// record and one finding (distinct finding_hash so merges don't dedup).
func writeGlobFixture(t *testing.T, path, host, hash, module string) {
	t.Helper()
	body := `{"type":"http_record","data":{"url":"http://` + host + `/x","method":"GET","status_code":200,"host":"` + host + `"}}
{"type":"finding","data":{"finding_hash":"` + hash + `","module_id":"` + module + `","module_name":"` + module + `","severity":"high","confidence":"firm","url":"http://` + host + `/x","hostname":"` + host + `","description":"d"}}
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestOpenGlobDBMergesMatches(t *testing.T) {
	dir := t.TempDir()
	writeGlobFixture(t, filepath.Join(dir, "scan-a.jsonl"), "a.example", "hash-a", "xss-reflected")
	writeGlobFixture(t, filepath.Join(dir, "scan-b.jsonl"), "b.example", "hash-b", "sqli-error")

	// openGlobDB caches its connection process-wide; reset so it doesn't leak
	// into other tests in this package.
	defer clicommon.ResetDBCache()

	db, err := openGlobDB(filepath.Join(dir, "scan-*.jsonl"), globDBSkipSet{})
	if err != nil {
		t.Fatalf("openGlobDB: %v", err)
	}

	ctx := context.Background()
	var findings []*database.Finding
	if err := db.NewSelect().Model(&findings).Scan(ctx); err != nil {
		t.Fatalf("scan findings: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings merged across the glob, got %d", len(findings))
	}

	var records []*database.HTTPRecord
	if err := db.NewSelect().Model(&records).Scan(ctx); err != nil {
		t.Fatalf("scan records: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 HTTP records merged across the glob, got %d", len(records))
	}
}

func TestOpenGlobDBErrors(t *testing.T) {
	t.Run("no match", func(t *testing.T) {
		defer clicommon.ResetDBCache()
		if _, err := openGlobDB(filepath.Join(t.TempDir(), "nope-*.sqlite"), globDBSkipSet{}); err == nil {
			t.Fatal("expected an error when the glob matches no files")
		}
	})

	t.Run("invalid pattern", func(t *testing.T) {
		defer clicommon.ResetDBCache()
		if _, err := openGlobDB("[", globDBSkipSet{}); err == nil {
			t.Fatal("expected an error for a malformed glob pattern")
		}
	})

	t.Run("all matches unimportable", func(t *testing.T) {
		defer clicommon.ResetDBCache()
		dir := t.TempDir()
		// A matched-but-garbage file is skipped; with none loadable, error out.
		if err := os.WriteFile(filepath.Join(dir, "junk-1.jsonl"), []byte("not json at all\n"), 0o644); err != nil {
			t.Fatalf("write junk: %v", err)
		}
		if _, err := openGlobDB(filepath.Join(dir, "junk-*.jsonl"), globDBSkipSet{}); err == nil {
			t.Fatal("expected an error when no matched file could be loaded")
		}
	})
}
