package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const decodeTestBody = "<html><title>Inbox</title><body>needle-in-the-body</body></html>"

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write([]byte(s))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ingestedPair is an exchange as an ingest path hands it over: the response in
// its wire coding.
func ingestedPair(t *testing.T, rawResponse []byte) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.ParseRawRequestWithURL("GET /inbox HTTP/1.1\r\nHost: mail.test\r\n\r\n", "https://mail.test/inbox")
	if err != nil {
		t.Fatal(err)
	}
	return rr.WithResponse(httpmsg.NewHttpResponse(rawResponse))
}

func gzipResponse(t *testing.T) []byte {
	t.Helper()
	body := gzipped(t, decodeTestBody)
	return append([]byte(fmt.Sprintf("HTTP/2 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nX-Trace: 1\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
}

func TestEnrichStoresIngestedBodiesDecoded(t *testing.T) {
	rec := &HTTPRecord{}
	if err := rec.FromHttpRequestResponse(ingestedPair(t, gzipResponse(t))); err != nil {
		t.Fatal(err)
	}
	stored := string(rec.RawResponse)
	want := "HTTP/2 200 OK\r\nContent-Type: text/html\r\nX-Trace: 1\r\nContent-Length: " +
		fmt.Sprint(len(decodeTestBody)) + "\r\n\r\n" + decodeTestBody
	if stored != want {
		t.Fatalf("stored response:\n%q\nwant\n%q", stored, want)
	}
	if rec.ResponseDecodedFrom != "gzip" {
		t.Errorf("ResponseDecodedFrom = %q, want gzip", rec.ResponseDecodedFrom)
	}
	if rec.ResponseContentLength != int64(len(decodeTestBody)) || rec.ResponseTitle != "Inbox" {
		t.Errorf("derived columns read the encoded body: length %d, title %q", rec.ResponseContentLength, rec.ResponseTitle)
	}
	sum := sha256.Sum256(rec.RawResponse)
	if rec.ResponseHash != hex.EncodeToString(sum[:]) {
		t.Error("response_hash is not the hash of the stored bytes")
	}
}

func TestEnrichKeepsWhatItCannotDecode(t *testing.T) {
	for name, raw := range map[string]string{
		"a plaintext body under gzip": "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nnot compressed",
		"an unknown coding":           "HTTP/1.1 200 OK\r\nContent-Encoding: compress\r\n\r\nxyz",
		"a stacked coding":            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip, br\r\n\r\nxyz",
		"no coding":                   "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nplain",
	} {
		rec := &HTTPRecord{}
		if err := rec.FromHttpRequestResponse(ingestedPair(t, []byte(raw))); err != nil {
			t.Fatal(err)
		}
		if string(rec.RawResponse) != raw || rec.ResponseDecodedFrom != "" {
			t.Errorf("%s: stored %q (decoded from %q), want it as received", name, rec.RawResponse, rec.ResponseDecodedFrom)
		}
	}
}

func TestEnrichDecodesAChunkedBody(t *testing.T) {
	body := gzipped(t, decodeTestBody)
	chunked := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" + chunked
	rec := &HTTPRecord{}
	if err := rec.FromHttpRequestResponse(ingestedPair(t, []byte(raw))); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(decodeTestBody), decodeTestBody)
	if string(rec.RawResponse) != want {
		t.Errorf("stored %q, want %q", rec.RawResponse, want)
	}
}

// Re-importing the same encoded exchange is unchanged: the stored hash is of
// the decoded bytes, and decoding is deterministic.
func TestReimportOfADecodedRecordIsUnchanged(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	raw := gzipResponse(t)
	uuid, outcome, err := repo.UpsertSnapshotRecord(ctx, ingestedPair(t, raw), RecordSourceBurp, "")
	if err != nil || outcome != "inserted" {
		t.Fatalf("first import = %q, %v", outcome, err)
	}
	_, outcome, err = repo.UpsertSnapshotRecord(ctx, ingestedPair(t, raw), RecordSourceBurp, "")
	if err != nil || outcome != "unchanged" {
		t.Fatalf("re-import = %q, %v; want unchanged", outcome, err)
	}
	got, err := repo.GetRecordByUUID(ctx, uuid)
	if err != nil {
		t.Fatal(err)
	}
	if got.ResponseDecodedFrom != "gzip" || !strings.Contains(string(got.RawResponse), "needle-in-the-body") {
		t.Errorf("stored row: decoded_from %q, body readable %v", got.ResponseDecodedFrom,
			strings.Contains(string(got.RawResponse), "needle-in-the-body"))
	}
}

// The one-time backfill decodes ingested rows written before decoding at
// storage, and leaves records vigolium fetched itself alone.
func TestBackfillDecodesStoredIngestedBodies(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	raw := gzipResponse(t)
	for _, r := range []struct{ uuid, source string }{{"rec-ingest", RecordSourceIngestCLI}, {"rec-scan", RecordSourceScanner}} {
		rec := &HTTPRecord{
			UUID: r.uuid, ProjectUUID: "p", Scheme: "https", Hostname: "mail.test", Port: 443,
			Method: "GET", Path: "/inbox", URL: "https://mail.test/inbox", HTTPVersion: "HTTP/1.1",
			RequestHash: r.uuid, HasResponse: true, StatusCode: 200, ResponseContentType: "text/html",
			RawResponse: raw, Source: r.source,
		}
		if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	n, err := db.backfillDecodedResponses(ctx)
	if err != nil || n != 1 {
		t.Fatalf("backfill decoded %d, %v; want 1", n, err)
	}
	repo := NewRepository(db)
	ingested, _ := repo.GetRecordByUUID(ctx, "rec-ingest")
	if ingested.ResponseDecodedFrom != "gzip" || !strings.HasSuffix(string(ingested.RawResponse), decodeTestBody) ||
		ingested.ResponseTitle != "Inbox" || ingested.ResponseContentLength != int64(len(decodeTestBody)) {
		t.Errorf("ingested row not decoded: %+v", ingested)
	}
	sum := sha256.Sum256(ingested.RawResponse)
	if ingested.ResponseHash != hex.EncodeToString(sum[:]) {
		t.Error("backfilled response_hash is not the hash of the stored bytes")
	}
	scanned, _ := repo.GetRecordByUUID(ctx, "rec-scan")
	if !bytes.Equal(scanned.RawResponse, raw) || scanned.ResponseDecodedFrom != "" {
		t.Error("a scanner record was rewritten")
	}
	// Idempotent: a decoded row is not a candidate again.
	if n, err := db.backfillDecodedResponses(ctx); err != nil || n != 0 {
		t.Errorf("second backfill decoded %d, %v; want 0", n, err)
	}
}
