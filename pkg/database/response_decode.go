package database

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http/httputil"
	"slices"
	"strconv"
	"strings"

	"github.com/uptrace/bun"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/contentcoding"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Ingested bodies are stored decoded.
//
// Traffic vigolium fetches itself reaches the store already decoded (the
// requester's response chain removes the content-coding). Traffic that ARRIVES
// — `vigolium ingest`, POST /api/ingest-http, the ingest proxy, the Burp/Caido
// bridge — carries whatever the wire carried, often a gzip or brotli body. Kept
// encoded, `traffic --body`, `--search` and every reader of raw_response see
// compressed bytes and must each decode on their own. EnrichFromHttpRequestResponse
// is the one place every record is converted before it is stored, so decoding
// happens there, once, for every source.
//
// What is stored for a decoded record:
//
//   - raw_response is a self-consistent HTTP message: the original status line
//     and headers in their order, minus Content-Encoding (and Transfer-Encoding
//     when the body was chunked), with Content-Length set to the decoded body.
//     Keeping a Content-Encoding header over a plaintext body would make every
//     HTTP parser decode it a second time, which is the bug a stale header
//     already caused once in the requester (pkg/http stripRawhttpDecodedEncoding).
//   - response_decoded_from records the content-coding the wire carried
//     ("gzip", "br", …), so the fact that the bytes were transformed is never
//     lost; NULL means the body is stored exactly as received.
//
// One layer only, and only a coding pkg/contentcoding decodes. A stacked value
// ("gzip, br"), an unknown coding, bytes that do not decode, or a decoded body
// over maxDecodedStoredBody are stored as received. response_hash is computed
// over the stored (decoded) bytes, and decoding is deterministic, so
// re-importing the same exchange hashes the same and UpsertSnapshotRecord
// reports it unchanged.

// maxDecodedStoredBody bounds a decoded response body: the requester's own
// body read cap (pkg/http.MaxBodyRead, 30 MB), so an ingested body is never
// stored larger than one vigolium would have fetched.
const maxDecodedStoredBody = 30 << 20

// decodeStoredResponse returns raw with one content-coding layer removed and
// the coding it removed, or ok false when raw is to be stored as received.
func decodeStoredResponse(resp *httpmsg.HttpResponse) (decoded []byte, coding string, ok bool) {
	if resp == nil {
		return nil, "", false
	}
	coding = contentcoding.Normalize(resp.Header("Content-Encoding"))
	if coding == "" || coding == "identity" || !contentcoding.Supported(coding) {
		return nil, "", false
	}
	head := resp.Head()
	body := resp.Body()
	if len(head) == 0 || len(body) == 0 {
		return nil, "", false
	}
	chunked := strings.Contains(strings.ToLower(resp.Header("Transfer-Encoding")), "chunked")
	if chunked {
		plain, err := io.ReadAll(io.LimitReader(httputil.NewChunkedReader(bytes.NewReader(body)), maxDecodedStoredBody+1))
		if err != nil || len(plain) > maxDecodedStoredBody {
			return nil, "", false
		}
		body = plain
	}
	plain, err := contentcoding.Decode(coding, body, maxDecodedStoredBody)
	if err != nil {
		return nil, "", false
	}
	drop := []string{"content-encoding", "content-length"}
	if chunked {
		drop = append(drop, "transfer-encoding")
	}
	return rewriteHead(head, drop, "Content-Length: "+strconv.Itoa(len(plain)), plain), coding, true
}

// rewriteHead returns head (status line, headers, blank line) without the
// headers named in drop (lower case), with extra appended as the last header,
// followed by body — the whole message in one buffer. The status line and
// every other header keep their bytes and order; the line terminator is the
// one head uses.
func rewriteHead(head []byte, drop []string, extra string, body []byte) []byte {
	eol := []byte("\r\n")
	if !bytes.Contains(head, eol) {
		eol = eol[1:]
	}
	out := make([]byte, 0, len(head)+len(extra)+2*len(eol)+len(body))
	rest := bytes.TrimRight(head, "\r\n")
	for i := 0; ; i++ {
		line, after, more := bytes.Cut(rest, eol)
		name, _, _ := bytes.Cut(line, []byte(":"))
		if i == 0 || !containsFold(drop, bytes.TrimSpace(name)) {
			out = append(out, line...)
			out = append(out, eol...)
		}
		if !more {
			break
		}
		rest = after
	}
	out = append(out, extra...)
	out = append(out, eol...)
	out = append(out, eol...)
	return append(out, body...)
}

func containsFold(list []string, s []byte) bool {
	for _, v := range list {
		if bytes.EqualFold([]byte(v), s) {
			return true
		}
	}
	return false
}

// decodedBackfillSources are the sources whose stored bodies may still carry
// their wire coding: ingested and bridged traffic (IngestRecordSources) plus
// out-of-scope ingested context. Records vigolium fetched itself were decoded
// by the requester before they were stored.
var decodedBackfillSources = append(slices.Clone(IngestRecordSources), RecordSourceIngestContext)

// decodedBackfillMaxRows bounds the one-time backfill: the rows it reads, so
// opening a very large store pays a bounded cost once. Rows past it stay as
// stored (their response_decoded_from stays NULL), which every reader already
// handles; a re-import of one of them decodes it.
const decodedBackfillMaxRows = 50000

// backfillDecodedResponses decodes the stored bodies of ingested records
// written before decoding at storage existed (schema v6's one-time pass, see
// CreateSchema). Every response-derived column is recomputed from the decoded
// bytes by deriveResponseColumns, as EnrichFromHttpRequestResponse sets them.
// Best effort: a row that fails to decode or update is left as it was.
func (db *DB) backfillDecodedResponses(ctx context.Context) (int, error) {
	type row struct {
		UUID        string `bun:"uuid"`
		Path        string `bun:"path"`
		URL         string `bun:"url"`
		ContentType string `bun:"response_content_type"`
		RawResponse []byte `bun:"raw_response"`
	}
	return db.runBackfill(ctx, "backfill decoded responses", decodedBackfillMaxRows,
		func(ctx context.Context, after string, limit int) (string, int, []backfillUpdate, error) {
			var page []row
			if err := db.NewSelect().
				TableExpr("http_records").
				ColumnExpr("uuid, path, url, response_content_type, raw_response").
				Where("has_response = ?", true).
				Where("response_decoded_from IS NULL").
				Where("source IN (?)", bun.List(decodedBackfillSources)).
				Where("uuid > ?", after).
				OrderExpr("uuid ASC").
				Limit(int64(limit)).
				Scan(ctx, &page); err != nil || len(page) == 0 {
				return after, 0, nil, err
			}
			var updates []backfillUpdate
			for _, r := range page {
				raw, coding, ok := decodeStoredResponse(httpmsg.NewHttpResponse(r.RawResponse))
				if !ok {
					continue
				}
				cols := deriveResponseColumns(httpmsg.NewHttpResponse(raw), r.ContentType, r.Path, r.URL)
				updates = append(updates, backfillUpdate{uuid: r.UUID, apply: func(ctx context.Context, idb bun.IDB) error {
					_, err := idb.NewUpdate().
						TableExpr("http_records").
						Set("raw_response = ?", raw).
						Set("response_decoded_from = ?", coding).
						Set("response_hash = ?", cols.Hash).
						Set("response_norm_hash = ?", cols.NormHash).
						Set("response_words = ?", cols.Words).
						Set("response_content_length = ?", cols.ContentLength).
						Set("response_title = NULLIF(?, '')", cols.Title).
						Where("uuid = ?", r.UUID).
						Exec(ctx)
					return err
				}})
			}
			return page[len(page)-1].UUID, len(page), updates, nil
		})
}

// backfillPage is how many rows a one-time backfill reads, and updates in one
// transaction, at a time.
const backfillPage = 200

// backfillUpdate is one row's UPDATE in a one-time backfill, run against the
// page's transaction or, on the fallback, the database itself.
type backfillUpdate struct {
	uuid  string
	apply func(ctx context.Context, idb bun.IDB) error
}

// runBackfill is the one-time backfills' bounded pass over http_records in
// uuid order: fetch reads up to limit rows with uuid > after and returns the
// last uuid it read, how many rows it read, and the updates for the rows that
// need one. At most maxRows rows are read. Returns how many rows were updated;
// only a failed read ends the pass early.
func (db *DB) runBackfill(ctx context.Context, name string, maxRows int,
	fetch func(ctx context.Context, after string, limit int) (string, int, []backfillUpdate, error),
) (int, error) {
	updated, read := 0, 0
	after := ""
	for read < maxRows {
		last, n, updates, err := fetch(ctx, after, min(backfillPage, maxRows-read))
		if err != nil {
			return updated, fmt.Errorf("%s: %w", name, err)
		}
		after = last
		read += n
		updated += db.applyBackfillPage(ctx, name, updates)
		if n < backfillPage {
			break
		}
	}
	return updated, nil
}

// applyBackfillPage runs one page's updates in a single transaction. A failed
// row aborts that transaction (on Postgres it poisons every statement after
// it), so the page is then retried row by row outside one: each row stays
// best effort, a failure leaving only that row as it was.
func (db *DB) applyBackfillPage(ctx context.Context, name string, updates []backfillUpdate) int {
	if len(updates) == 0 {
		return 0
	}
	err := db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for _, u := range updates {
			if err := u.apply(ctx, tx); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		return len(updates)
	}
	n := 0
	for _, u := range updates {
		if err := u.apply(ctx, db.DB); err != nil {
			zap.L().Debug(name+": update failed", zap.String("uuid", u.uuid), zap.Error(err))
			continue
		}
		n++
	}
	return n
}
