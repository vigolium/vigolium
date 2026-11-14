package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// fixtureRecord is one exchange seeded into a compaction fixture.
type fixtureRecord struct {
	method, path, contentType string
	reqBody, respBody         []byte
	sentAt                    time.Time
	project                   string
}

// seedRecord stores one exchange through the real write path and pins its
// sent_at, so ordering and age filters are deterministic.
func seedRecord(t *testing.T, db *DB, f fixtureRecord) string {
	t.Helper()
	method := f.method
	if method == "" {
		method = "GET"
	}
	rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: t.example.com\r\nContent-Length: %d\r\n\r\n", method, f.path, len(f.reqBody))
	rr, err := httpmsg.ParseRawRequest(rawReq + string(f.reqBody))
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	resp := httpmsg.NewHttpResponse([]byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nX-Probe: kept\r\n\r\n%s",
		f.contentType, len(f.respBody), f.respBody)))
	rr = rr.WithResponse(resp)
	project := f.project
	if project == "" {
		project = DefaultProjectUUID
	}
	uuid, err := NewRepository(db).SaveRecord(context.Background(), rr, "test", project)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}
	mustExec(t, db, "UPDATE http_records SET sent_at = ? WHERE uuid = ?", sentAtText(f.sentAt), uuid)
	return uuid
}

// body returns n deterministic bytes that do not compress to nothing, so file
// sizes in the budget tests move with the bytes stored.
func body(n int, seed byte) []byte {
	b := make([]byte, n)
	x := uint32(seed) + 1
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = 'a' + byte(x>>24)%26
	}
	return b
}

func loadRecord(t *testing.T, db *DB, uuid string) *HTTPRecord {
	t.Helper()
	rec, err := NewRepository(db).GetRecordByUUID(context.Background(), uuid)
	if err != nil {
		t.Fatalf("GetRecordByUUID(%s): %v", uuid, err)
	}
	return rec
}

func defaultCompactOptions() CompactOptions {
	return CompactOptions{BodyOver: 64 << 10, KeepHead: 4 << 10, Vacuum: true}
}

var day0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func TestCompactMessage(t *testing.T) {
	headers := "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n"
	b := body(1000, 1)
	out, part, ok := compactMessage([]byte(headers+string(b)), 100, 10)
	if !ok {
		t.Fatal("a body over the threshold must compact")
	}
	if string(out) != headers+string(b[:10]) {
		t.Fatalf("compacted message = %q, want headers + 10 body bytes", out)
	}
	digest := sha256.Sum256(b)
	if part.OriginalLength != 1000 || part.SHA256 != hex.EncodeToString(digest[:]) || part.KeptLength != 10 {
		t.Fatalf("part = %+v", part)
	}

	// The threshold is on the BODY: a message whose headers push it over is not
	// compacted.
	bigHeaders := "HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("p", 500) + "\r\n\r\nshort"
	if _, _, ok := compactMessage([]byte(bigHeaders), 100, 10); ok {
		t.Fatal("a short body behind long headers must not compact")
	}
	// No separator: not a message this can split.
	if _, _, ok := compactMessage(bytes.Repeat([]byte("x"), 500), 100, 10); ok {
		t.Fatal("a message without a header/body separator must be left alone")
	}
}

func TestCompactBodies_KeepsTheRecordAndRecordsTheOriginal(t *testing.T) {
	db, _ := newFileDB(t, "compact.sqlite")
	ctx := context.Background()

	img := body(300<<10, 2)
	js := body(200<<10, 3)
	post := body(100<<10, 4)
	imgID := seedRecord(t, db, fixtureRecord{path: "/static/hero.png", contentType: "image/png", respBody: img, sentAt: day0})
	jsID := seedRecord(t, db, fixtureRecord{path: "/static/app.js?v=3", contentType: "application/javascript; charset=utf-8", respBody: js, sentAt: day0.Add(time.Hour)})
	cdnJsID := seedRecord(t, db, fixtureRecord{path: "/cdn/Bundle.JS", contentType: "application/octet-stream", respBody: js, sentAt: day0.Add(2 * time.Hour)})
	smallID := seedRecord(t, db, fixtureRecord{path: "/index.html", contentType: "text/html", respBody: body(1024, 5), sentAt: day0.Add(3 * time.Hour)})
	postID := seedRecord(t, db, fixtureRecord{method: "POST", path: "/upload", contentType: "application/json", reqBody: post, respBody: []byte(`{"ok":true}`), sentAt: day0.Add(4 * time.Hour)})

	before := map[string]*HTTPRecord{}
	for _, id := range []string{imgID, jsID, cdnJsID, smallID, postID} {
		before[id] = loadRecord(t, db, id)
	}

	opts := defaultCompactOptions()
	opts.SkipContentTypes = []string{"*javascript*", "*ecmascript*"}
	opts.SkipPaths = []string{"*.js", "*.mjs"}
	stamp := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	opts.Now = func() time.Time { return stamp }
	sum, err := db.CompactBodies(ctx, opts)
	if err != nil {
		t.Fatalf("CompactBodies: %v", err)
	}
	if sum.RecordsCompacted != 2 || sum.ResponseBodiesCompacted != 1 || sum.RequestBodiesCompacted != 1 {
		t.Fatalf("summary = %+v, want the image response and the POST request", sum)
	}
	if sum.BodyBytesBefore != int64(len(img)+len(post)) || sum.BodyBytesAfter != 2*(4<<10) {
		t.Fatalf("body bytes = %d -> %d", sum.BodyBytesBefore, sum.BodyBytesAfter)
	}
	if !sum.Vacuumed || sum.DBBytesAfter >= sum.DBBytesBefore {
		t.Fatalf("db bytes %d -> %d, vacuumed=%v", sum.DBBytesBefore, sum.DBBytesAfter, sum.Vacuumed)
	}

	// The image: head kept behind the original header block, and every column
	// that describes the exchange unchanged.
	got := loadRecord(t, db, imgID)
	was := before[imgID]
	wantHead := string(was.RawResponse[:len(was.RawResponse)-len(img)]) + string(img[:4<<10])
	if string(got.RawResponse) != wantHead {
		t.Fatalf("raw_response is not header block + 4 KiB head (len %d)", len(got.RawResponse))
	}
	if !strings.Contains(string(got.RawResponse), "X-Probe: kept") {
		t.Fatal("headers must survive compaction")
	}
	if got.URL != was.URL || got.StatusCode != was.StatusCode || got.ResponseContentType != was.ResponseContentType ||
		got.ResponseContentLength != was.ResponseContentLength || got.ResponseHash != was.ResponseHash ||
		got.ContentHash != was.ContentHash || !got.SentAt.Equal(was.SentAt) {
		t.Fatalf("a describing column changed:\nbefore %+v\nafter  %+v", was, got)
	}
	m := got.BodyCompaction
	digest := sha256.Sum256(img)
	if m == nil || m.Version != 1 || !m.CompactedAt.Equal(stamp) || m.KeepHead != 4<<10 || m.Request != nil ||
		m.Response == nil || m.Response.OriginalLength != int64(len(img)) || m.Response.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("marker = %+v", m)
	}

	// The POST: only the request body was over the threshold.
	gotPost := loadRecord(t, db, postID)
	if gotPost.BodyCompaction == nil || gotPost.BodyCompaction.Request == nil || gotPost.BodyCompaction.Response != nil {
		t.Fatalf("POST marker = %+v", gotPost.BodyCompaction)
	}
	if string(gotPost.RawResponse) != string(before[postID].RawResponse) {
		t.Fatal("a short response must be left as captured")
	}

	// Protected by content type, by path (case-insensitive, query ignored), and
	// under the threshold: all untouched.
	for _, id := range []string{jsID, cdnJsID, smallID} {
		r := loadRecord(t, db, id)
		if r.BodyCompaction != nil || string(r.RawResponse) != string(before[id].RawResponse) {
			t.Fatalf("record %s (%s) must be untouched", id, r.Path)
		}
	}

	// Idempotent: a second identical pass changes nothing.
	again, err := db.CompactBodies(ctx, opts)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if again.RecordsCompacted != 0 {
		t.Fatalf("second pass compacted %d records", again.RecordsCompacted)
	}
	if after := loadRecord(t, db, imgID); after.BodyCompaction.Response.SHA256 != m.Response.SHA256 {
		t.Fatal("a compacted body's recorded hash must be the original's, forever")
	}

	// Lifting the protection compacts the scripts, and leaves the rest as is.
	all, err := db.CompactBodies(ctx, defaultCompactOptions())
	if err != nil {
		t.Fatalf("unfiltered pass: %v", err)
	}
	if all.RecordsCompacted != 2 {
		t.Fatalf("unfiltered pass compacted %d, want the two scripts", all.RecordsCompacted)
	}
}

func TestCompactBodies_OlderThanAndProjectScope(t *testing.T) {
	db, _ := newFileDB(t, "scope.sqlite")
	ctx := context.Background()
	oldID := seedRecord(t, db, fixtureRecord{path: "/old.png", contentType: "image/png", respBody: body(100<<10, 1), sentAt: day0})
	newID := seedRecord(t, db, fixtureRecord{path: "/new.png", contentType: "image/png", respBody: body(100<<10, 2), sentAt: day0.Add(48 * time.Hour)})
	otherID := seedRecord(t, db, fixtureRecord{path: "/other.png", contentType: "image/png", respBody: body(100<<10, 3), sentAt: day0, project: "other-project"})

	opts := defaultCompactOptions()
	cutoff := day0.Add(24 * time.Hour)
	opts.OlderThan = &cutoff
	opts.ProjectUUID = DefaultProjectUUID
	sum, err := db.CompactBodies(ctx, opts)
	if err != nil {
		t.Fatalf("CompactBodies: %v", err)
	}
	if sum.RecordsCompacted != 1 || loadRecord(t, db, oldID).BodyCompaction == nil {
		t.Fatalf("summary %+v: only the old record of this project compacts", sum)
	}
	if loadRecord(t, db, newID).BodyCompaction != nil {
		t.Fatal("a record newer than --older-than must be kept whole")
	}
	if loadRecord(t, db, otherID).BodyCompaction != nil {
		t.Fatal("another project's record must be kept whole")
	}

	opts.ProjectUUID = ""
	sum, err = db.CompactBodies(ctx, opts)
	if err != nil || sum.RecordsCompacted != 1 || loadRecord(t, db, otherID).BodyCompaction == nil {
		t.Fatalf("store-wide pass: %+v %v", sum, err)
	}
}

func TestCompactBodies_DryRunChangesNothing(t *testing.T) {
	db, path := newFileDB(t, "dry.sqlite")
	id := seedRecord(t, db, fixtureRecord{path: "/a.png", contentType: "image/png", respBody: body(200<<10, 1), sentAt: day0})
	opts := defaultCompactOptions()
	opts.DryRun = true
	sum, err := db.CompactBodies(context.Background(), opts)
	if err != nil {
		t.Fatalf("CompactBodies: %v", err)
	}
	if !sum.DryRun || sum.RecordsCompacted != 1 || sum.Vacuumed {
		t.Fatalf("summary = %+v", sum)
	}
	if loadRecord(t, db, id).BodyCompaction != nil {
		t.Fatal("a dry run must not write")
	}
	if sum.DBBytesAfter >= sum.DBBytesBefore {
		t.Fatalf("dry run should estimate a smaller file: %d -> %d", sum.DBBytesBefore, sum.DBBytesAfter)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestCompactBodies_BudgetCompactsOldestFirst(t *testing.T) {
	db, _ := newFileDB(t, "budget.sqlite")
	ctx := context.Background()
	const n = 24
	ids := make([]string, n)
	for i := range n {
		// Inserted newest first, so "oldest first" has to come from sent_at and
		// not from insertion order.
		at := day0.Add(time.Duration(n-i) * time.Hour)
		ids[n-1-i] = seedRecord(t, db, fixtureRecord{
			path: fmt.Sprintf("/asset/%d.bin", n-i), contentType: "application/octet-stream",
			respBody: body(128<<10, byte(i)), sentAt: at,
		})
	}
	if err := db.vacuum(ctx); err != nil {
		t.Fatal(err)
	}
	full := db.fileBytes()

	// Room for roughly half the bodies.
	opts := defaultCompactOptions()
	opts.MaxDBSize = full / 2
	sum, err := db.CompactBodies(ctx, opts)
	if err != nil {
		t.Fatalf("CompactBodies: %v", err)
	}
	if !sum.BudgetMet || sum.DBBytesAfter > opts.MaxDBSize {
		t.Fatalf("budget not met: %+v (full %d)", sum, full)
	}
	if sum.RecordsCompacted == 0 || sum.RecordsCompacted == n || sum.Remaining != n-sum.RecordsCompacted {
		t.Fatalf("a half budget should compact some and leave the rest: %+v", sum)
	}
	// ids is oldest first: the first RecordsCompacted are compacted, the rest are not.
	for i, id := range ids {
		compacted := loadRecord(t, db, id).BodyCompaction != nil
		if compacted != (int64(i) < sum.RecordsCompacted) {
			t.Fatalf("record %d (oldest=0) compacted=%v; the budget must take the oldest first", i, compacted)
		}
	}

	// An unreachable budget compacts everything selected and says it fell short.
	opts.MaxDBSize = 1
	sum, err = db.CompactBodies(ctx, opts)
	if err != nil {
		t.Fatalf("CompactBodies: %v", err)
	}
	if sum.BudgetMet || sum.Remaining != 0 {
		t.Fatalf("unreachable budget: %+v", sum)
	}
	for i, id := range ids {
		if loadRecord(t, db, id).BodyCompaction == nil {
			t.Fatalf("record %d left whole under an unreachable budget", i)
		}
	}
	var count int64
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM http_records").Scan(&count); err != nil || count != n {
		t.Fatalf("records = %d (%v); compaction must never delete", count, err)
	}
}

func TestCompactBodies_BudgetAlreadyMetIsANoOp(t *testing.T) {
	db, _ := newFileDB(t, "under.sqlite")
	id := seedRecord(t, db, fixtureRecord{path: "/a.png", contentType: "image/png", respBody: body(100<<10, 1), sentAt: day0})
	opts := defaultCompactOptions()
	opts.MaxDBSize = 1 << 30
	sum, err := db.CompactBodies(context.Background(), opts)
	if err != nil {
		t.Fatalf("CompactBodies: %v", err)
	}
	if !sum.BudgetMet || sum.RecordsCompacted != 0 || loadRecord(t, db, id).BodyCompaction != nil {
		t.Fatalf("a store under budget must be left alone: %+v", sum)
	}
}

func TestCompactBodies_OverBudgetVacuumsOnlyWhenPagesAreFree(t *testing.T) {
	db, _ := newFileDB(t, "free.sqlite")
	ctx := context.Background()
	seedRecord(t, db, fixtureRecord{path: "/a.png", contentType: "image/png", respBody: body(300<<10, 1), sentAt: day0})
	seedRecord(t, db, fixtureRecord{path: "/app.js", contentType: "application/javascript", respBody: body(300<<10, 2), sentAt: day0})
	if err := db.vacuum(ctx); err != nil {
		t.Fatal(err)
	}

	// A --no-vacuum pass leaves the freed pages in the file.
	opts := defaultCompactOptions()
	opts.Vacuum = false
	opts.SkipPaths = []string{"*.js"}
	if sum, err := db.CompactBodies(ctx, opts); err != nil || sum.RecordsCompacted != 1 || sum.Vacuumed {
		t.Fatalf("no-vacuum pass: %+v %v", sum, err)
	}
	if db.freePages(ctx) == 0 {
		t.Fatal("a pass without VACUUM should leave free pages")
	}

	// Over budget with nothing left to select: the free pages are reclaimed.
	opts.Vacuum = true
	opts.MaxDBSize = 1
	sum, err := db.CompactBodies(ctx, opts)
	if err != nil || sum.RecordsCompacted != 0 || !sum.Vacuumed || sum.BudgetMet {
		t.Fatalf("reclaiming pass: %+v %v", sum, err)
	}

	// Again: nothing to compact and nothing to reclaim, so no rebuild.
	sum, err = db.CompactBodies(ctx, opts)
	if err != nil || sum.RecordsCompacted != 0 || sum.Vacuumed || sum.BudgetMet {
		t.Fatalf("idle pass over budget must not VACUUM: %+v %v", sum, err)
	}
}

func TestCompactFilter(t *testing.T) {
	f := newCompactFilter(CompactOptions{
		OnlyContentTypes: []string{"image/*"},
		OnlyPaths:        []string{"/media/*"},
		SkipPaths:        []string{"*.svg"},
	})
	cases := []struct {
		ct, path string
		want     bool
	}{
		{"image/png", "/a.png", true},
		{"IMAGE/JPEG; q=1", "/a.jpg", true},
		{"text/html", "/media/clip", true},
		{"text/html", "/page", false},
		{"image/svg+xml", "/logo.svg?x=1", false}, // skip wins over only
	}
	for _, c := range cases {
		if got := f.selects(compactCandidate{ContentType: c.ct, Path: c.path}); got != c.want {
			t.Errorf("selects(%q, %q) = %v, want %v", c.ct, c.path, got, c.want)
		}
	}
}

func TestCompactOptionsValidate(t *testing.T) {
	bad := []CompactOptions{
		{BodyOver: 0, KeepHead: 0},
		{BodyOver: 100, KeepHead: 100},
		{BodyOver: 100, KeepHead: -1},
		{BodyOver: 100, KeepHead: 10, MaxDBSize: -1},
		{BodyOver: 100, KeepHead: 10, SkipPaths: []string{" "}},
	}
	for i, o := range bad {
		if err := o.Validate(); err == nil {
			t.Errorf("case %d: %+v must be rejected", i, o)
		}
	}
	ok := CompactOptions{BodyOver: 100, KeepHead: 0}
	if err := ok.Validate(); err != nil {
		t.Errorf("keep-head 0 is valid: %v", err)
	}
}

func TestCompactBodies_RejectsPostgres(t *testing.T) {
	pg := &DB{driver: driverPostgres}
	if _, err := pg.CompactBodies(context.Background(), defaultCompactOptions()); !errors.Is(err, ErrCompactUnsupported) {
		t.Fatalf("postgres: %v", err)
	}
}
