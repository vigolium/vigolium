package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestHandSentExchangesAreStored(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello " + r.URL.Query().Get("q") + strings.Repeat("x", 20000)))
	}))
	defer srv.Close()
	st := seedC6Store(t)
	ctx := context.Background()
	countSource := func(source string) int {
		repo, closeDB := openC6Repo(t, st)
		defer closeDB()
		var n int
		if err := repo.DB().NewRaw("SELECT COUNT(*) FROM http_records WHERE source = ?", source).Scan(ctx, &n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// A single replay stores the exchange by default and names it.
	code, out, errOut := st.run(t, "replay", "-i", srv.URL+"/end?q=1", "-j")
	if code != 0 {
		t.Fatalf("replay: exit %d\n%s\n%s", code, out, errOut)
	}
	it := items(t, decodeOne(t, out))
	saved, _ := it[0]["saved_record_uuid"].(string)
	if saved == "" || countSource(database.RecordSourceReplay) != 1 {
		t.Fatalf("replay did not store its exchange: %s", out)
	}
	// It is evidence: a scan refuses to re-attack it.
	if code, out, _ := st.run(t, "scan", "--record-uuid", saved, "-j"); code != 2 || !strings.Contains(out, "evidence") {
		t.Fatalf("scan --record-uuid <replay record>: exit %d\n%s", code, out)
	}

	// --no-save stores nothing; --read-only stores nothing either.
	if code, out, _ := st.run(t, "replay", "-i", srv.URL+"/end?q=2", "--no-save", "-j"); code != 0 || strings.Contains(out, "saved_record_uuid") {
		t.Fatalf("replay --no-save: exit %d\n%s", code, out)
	}
	code, out, _ = st.run(t, "replay", "-i", srv.URL+"/end?q=3", "--once", "--read-only", "-j")
	if code != 0 || !strings.Contains(out, `"save_skipped":"read_only"`) {
		t.Fatalf("replay --once --read-only: exit %d\n%s", code, out)
	}
	if n := countSource(database.RecordSourceReplay); n != 1 {
		t.Fatalf("records with source replay = %d, want 1", n)
	}

	// --once: one send, the saved uuid, the final URL after redirects, a
	// bounded body.
	before := hits.Load()
	code, out, errOut = st.run(t, "replay", "-i", srv.URL+"/start", "--once", "-j")
	if code != 0 {
		t.Fatalf("replay --once: exit %d\n%s\n%s", code, out, errOut)
	}
	v := items(t, decodeOne(t, out))[0]
	if v["record_uuid"] == "" || v["saved"] != true || !strings.HasSuffix(v["final_url"].(string), "/end") ||
		v["body_truncated"] != true || len(v["body"].(string)) != replayOnceBodyCap || v["status"] != float64(200) {
		t.Fatalf("replay --once item: %v", v)
	}
	if sent := hits.Load() - before; sent != 2 { // /start and the redirect to /end
		t.Fatalf("replay --once sent %d requests, want the request and its redirect", sent)
	}

	// --dry-run sends nothing.
	before = hits.Load()
	if code, out, _ := st.run(t, "replay", "-i", srv.URL+"/end?q=4", "--dry-run", "-j"); code != 0 || !strings.Contains(out, `"dry_run":true`) {
		t.Fatalf("replay --dry-run: exit %d\n%s", code, out)
	}
	if hits.Load() != before {
		t.Fatal("replay --dry-run sent a request")
	}

	// fuzz stores nothing by default, the kept exchanges with --save, every
	// one with --save=all.
	if code, out, errOut := st.run(t, "fuzz", srv.URL+"/end?q=FUZZ", "-p", "a", "-p", "b", "-j"); code != 0 {
		t.Fatalf("fuzz: exit %d\n%s\n%s", code, out, errOut)
	}
	if n := countSource(database.RecordSourceFuzz); n != 0 {
		t.Fatalf("fuzz without --save stored %d", n)
	}
	code, out, errOut = st.run(t, "fuzz", srv.URL+"/end?q=FUZZ", "-p", "a", "-p", "b", "-p", "c", "--save=all", "-j")
	if code != 0 {
		t.Fatalf("fuzz --save=all: exit %d\n%s\n%s", code, out, errOut)
	}
	if n := countSource(database.RecordSourceFuzz); n != 3 || !strings.Contains(out, "saved_record_uuids") {
		t.Fatalf("fuzz --save=all stored %d, want 3\n%s", n, out)
	}
	if code, out, _ := st.run(t, "fuzz", srv.URL+"/end?q=FUZZ", "-p", "a", "--save=some", "-j"); code != 2 {
		t.Fatalf("fuzz --save=some: exit %d\n%s", code, out)
	}
}
