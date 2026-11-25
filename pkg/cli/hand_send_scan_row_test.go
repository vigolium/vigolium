package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// A hand-sent save stores its record under a scans row of its own, created
// with the invocation's caller tags: `replay --caller-tag` leaves a record
// whose scan_uuid joins to a completed "replay" row carrying the tags.
func TestReplaySaveJoinsATaggedScanRow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	st := seedC6Store(t)

	code, out, errOut := st.run(t, "replay", "-i", srv.URL+"/tagged?q=1", "-j",
		"--caller-tag", "engagement=e7", "--caller-tag", "leg=confirm")
	if code != 0 {
		t.Fatalf("replay: exit %d\n%s\n%s", code, out, errOut)
	}
	saved, _ := items(t, decodeOne(t, out))[0]["saved_record_uuid"].(string)
	if saved == "" {
		t.Fatalf("replay stored nothing: %s", out)
	}

	repo, closeDB := openC6Repo(t, st)
	defer closeDB()
	ctx := context.Background()
	rec, err := repo.GetRecordByUUID(ctx, saved)
	if err != nil || rec.ScanUUID == "" {
		t.Fatalf("saved record has no scan_uuid (%v)", err)
	}
	row, err := repo.GetScanByUUID(ctx, rec.ScanUUID)
	if err != nil {
		t.Fatalf("the record's scan_uuid %s has no scans row: %v", rec.ScanUUID, err)
	}
	if row.Name != "replay" || row.Status != "completed" || !slices.Equal(row.Tags, []string{"engagement=e7", "leg=confirm"}) {
		t.Fatalf("scan row = name %q status %q tags %v", row.Name, row.Status, row.Tags)
	}

	// A malformed tag is refused before anything is sent or stored.
	if code, out, _ := st.run(t, "replay", "-i", srv.URL+"/tagged?q=2", "-j", "--caller-tag", "nokey"); code != 2 {
		t.Fatalf("replay --caller-tag nokey: exit %d, want 2\n%s", code, out)
	}
}
