package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// scan --record-uuid runs the modules against the named record and no other.
func TestScanRecordUUIDScansOnlyThatRecord(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>ok " + r.URL.RawQuery + "</html>"))
	}))
	defer srv.Close()

	st := seedC6Store(t)
	repo, closeDB := openC6Repo(t, st)
	ctx := context.Background()
	save := func(path string) string {
		rr, err := httpmsg.GetRawRequestFromURL(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		id, err := repo.SaveRecord(ctx, rr, database.RecordSourceIngestCLI, database.DefaultProjectUUID)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	target := save("/target?q=1")
	save("/other?q=1")
	evidence, err := func() (string, error) {
		rr, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/evidence?q=1")
		return repo.SaveRecord(ctx, rr, database.RecordSourceFinding, database.DefaultProjectUUID)
	}()
	if err != nil {
		t.Fatal(err)
	}
	closeDB()

	code, out, errOut := st.run(t, "scan", "--record-uuid", target[:10], "-m", "reflected-ssti", "-c", "2", "--scanning-max-duration", "60s", "-j")
	if code != 0 {
		t.Fatalf("scan --record-uuid: exit %d\n%s\n%s", code, out, errOut)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits["/target"] == 0 {
		t.Fatalf("the named record was not scanned: %v", hits)
	}
	if hits["/other"] != 0 || hits["/evidence"] != 0 {
		t.Fatalf("records that were not named were scanned: %v", hits)
	}

	// Conflicts and bad references.
	for _, args := range [][]string{
		{"scan", "--record-uuid", target, "-t", srv.URL, "-j"},
		{"scan", "--record-uuid", target, "--all-records", "-j"},
		{"scan", "--record-uuid", target, "-S", "-j"},
		{"scan", "--record-uuid", evidence, "-j"},
	} {
		if code, out, _ := st.run(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2\n%s", args, code, out)
		}
	}
	if code, out, _ := st.run(t, "scan", "--record-uuid", "ffffffff-dead", "-j"); code != 1 || !strings.Contains(out, "record_not_found") {
		t.Errorf("unknown record: exit %d\n%s", code, out)
	}
}
