package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/internal/redact"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Import-time credential redaction (`import --redact credentials`).
//
// A store handed to another run (a board built from many runs' traffic, a
// carried seed) must not carry the sessions its runs held. The redaction masks
// every credential copy a stored exchange keeps, with redact.HTTPMessage as the
// one rule for the raw messages: the value of Authorization,
// Proxy-Authorization and every other credential header (redact.IsSensitiveHeader),
// each cookie value in Cookie and Set-Cookie (names and attributes kept), and
// sensitive query parameters on the request line. A value becomes
// redact.Placeholder, so a reader still sees that a request was authenticated,
// and as which cookie. Bodies are kept: they are the evidence.
//
// The columns derived from those bytes follow, so no copy survives beside the
// message: request_authorization, the url/path query, the parsed parameters,
// and the response hashes recomputed over the stored bytes. A redirect's
// Location is kept, in the message and in response_location alike, as the
// shared rule keeps it. request_hash stays the capture's, so the record still dedups
// against the same request.

// recordRedaction says which half of a record a redaction changed.
type recordRedaction struct {
	request  bool // raw_request, request_authorization, url, path, parameters
	response bool // raw_response and the response hashes
}

func (r recordRedaction) changed() bool { return r.request || r.response }

// RedactHeaderSet is the lowercased set of extra header names a redaction
// masks beside redact.IsSensitiveHeader's: the names a caller declared as
// credentials (`import --redact-header`). Nil when there are none.
func RedactHeaderSet(names []string) map[string]struct{} {
	if len(names) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			set[n] = struct{}{}
		}
	}
	return set
}

// RedactRecordCredentials masks the credentials rec carries, in place, and
// reports whether anything changed. extra names further credential headers
// (RedactHeaderSet).
func RedactRecordCredentials(rec *HTTPRecord, extra map[string]struct{}) bool {
	return redactRecord(rec, extra).changed()
}

func redactRecord(rec *HTTPRecord, extra map[string]struct{}) recordRedaction {
	var out recordRedaction
	if rec == nil {
		return out
	}
	if len(rec.RawRequest) > 0 {
		if red, ok := redactRawMessage(rec.RawRequest, extra); ok {
			rec.RawRequest = red
			out.request = true
			// The parsed parameters hold the cookie and query values verbatim
			// and their offsets into the old bytes: parse them again from the
			// stored message.
			if len(rec.Parameters) > 0 {
				if params, err := httpmsg.NewHttpRequest(rec.RawRequest).Parameters(); err == nil && len(params) > 0 {
					rec.Parameters = embeddedParams(params)
				} else {
					rec.Parameters = nil
				}
			}
		}
	}
	if rec.RequestAuthorization != "" && rec.RequestAuthorization != redact.Placeholder {
		rec.RequestAuthorization = redact.Placeholder
		out.request = true
	}
	if red := redact.URL(rec.URL); red != rec.URL {
		rec.URL = red
		out.request = true
	}
	if strings.ContainsAny(rec.Path, "?#") {
		if red := redact.URL(rec.Path); red != rec.Path {
			rec.Path = red
			out.request = true
		}
	}
	if len(rec.RawResponse) > 0 {
		if red, ok := redactRawMessage(rec.RawResponse, extra); ok {
			rec.RawResponse = red
			out.response = true
			cols := deriveResponseColumns(httpmsg.NewHttpResponse(rec.RawResponse), rec.ResponseContentType, rec.Path, rec.URL)
			rec.ResponseHash = cols.Hash
			rec.ResponseNormHash = cols.NormHash
			rec.ResponseWords = cols.Words
			rec.ResponseContentLength = cols.ContentLength
		}
	}
	return out
}

// redactRawMessage applies redact.HTTPMessage to raw without copying its body:
// only the header block (which is all the redaction touches) is converted, and
// the body is spliced back on when something changed. The head is passed with
// the same terminator it ended with, so redact.HTTPMessage splits it exactly
// as it would the whole message.
func redactRawMessage(raw []byte, extra map[string]struct{}) ([]byte, bool) {
	end, term := bytes.Index(raw, []byte("\r\n\r\n")), "\r\n\r\n"
	if end < 0 {
		end, term = bytes.Index(raw, []byte("\n\n")), "\n\n"
	}
	if end < 0 {
		in := string(raw)
		if red := redact.HTTPMessage(in, extra); red != in {
			return []byte(red), true
		}
		return raw, false
	}
	in := string(raw[:end]) + term
	red := redact.HTTPMessage(in, extra)
	if red == in {
		return raw, false
	}
	red = strings.TrimSuffix(red, term)
	out := make([]byte, 0, len(red)+len(raw)-end)
	out = append(out, red...)
	return append(out, raw[end:]...), true
}

// RedactFindingCredentials masks the credentials in the exchanges a finding
// carries inline (request, response, additional_evidence), in place, and
// reports whether anything changed. The finding's identity columns (url,
// matched_at, finding_hash) are left as stored, so it still dedups. extra names
// further credential headers (RedactHeaderSet).
func RedactFindingCredentials(f *Finding, extra map[string]struct{}) bool {
	if f == nil {
		return false
	}
	changed := false
	if red := redact.HTTPMessage(f.Request, extra); red != f.Request {
		f.Request = red
		changed = true
	}
	if red := redact.HTTPMessage(f.Response, extra); red != f.Response {
		f.Response = red
		changed = true
	}
	for i, ev := range f.AdditionalEvidence {
		if red := redact.HTTPMessage(ev, extra); red != ev {
			f.AdditionalEvidence[i] = red
			changed = true
		}
	}
	return changed
}

// recordRedactPage is how many records one redaction read holds: each carries
// its raw request and response.
const recordRedactPage = 200

// redactMergedRecordsTx redacts, inside a merge's transaction, the records
// whose uuids are in temp.<newTable>, and returns how many changed.
func redactMergedRecordsTx(ctx context.Context, tx *sql.Tx, newTable string, extra map[string]struct{}) (int, error) {
	q := `SELECT uuid, raw_request, raw_response, request_authorization, url, path,
		parameters, has_response, response_content_type
		FROM main.http_records
		WHERE uuid IN (SELECT uuid FROM temp.` + newTable + `) AND uuid > ?
		ORDER BY uuid LIMIT ?`
	changed := 0
	last := ""
	for {
		page, err := readRedactPage(ctx, tx, q, last)
		if err != nil {
			return changed, err
		}
		if len(page) == 0 {
			return changed, nil
		}
		last = page[len(page)-1].UUID
		for _, rec := range page {
			r := redactRecord(rec, extra)
			if !r.changed() {
				continue
			}
			if err := writeRecordRedaction(ctx, tx, rec, r); err != nil {
				return changed, err
			}
			changed++
		}
	}
}

// readRedactPage reads one page of the redaction query, drained before any
// write (a SQLite connection runs no statement while a cursor is open on it).
func readRedactPage(ctx context.Context, tx *sql.Tx, q, after string) ([]*HTTPRecord, error) {
	rows, err := tx.QueryContext(ctx, q, after, recordRedactPage)
	if err != nil {
		return nil, fmt.Errorf("read records to redact: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var page []*HTTPRecord
	for rows.Next() {
		var (
			rec                    HTTPRecord
			auth, params, respType sql.NullString
			hasResponse            sql.NullBool
		)
		if err := rows.Scan(&rec.UUID, &rec.RawRequest, &rec.RawResponse, &auth, &rec.URL, &rec.Path,
			&params, &hasResponse, &respType); err != nil {
			return nil, fmt.Errorf("scan record to redact: %w", err)
		}
		rec.RequestAuthorization = auth.String
		rec.HasResponse = hasResponse.Bool
		rec.ResponseContentType = respType.String
		if params.Valid && params.String != "" {
			// Unreadable parameters stay nil: a redacted request then stores
			// none, which keeps no credential copy (they re-derive from the
			// request).
			_ = json.Unmarshal([]byte(params.String), &rec.Parameters)
		}
		page = append(page, &rec)
	}
	return page, rows.Err()
}

// writeRecordRedaction stores the redacted columns of rec.
func writeRecordRedaction(ctx context.Context, tx *sql.Tx, rec *HTTPRecord, r recordRedaction) error {
	if r.request {
		var params any
		if len(rec.Parameters) > 0 {
			b, err := json.Marshal(rec.Parameters)
			if err != nil {
				return fmt.Errorf("encode redacted parameters: %w", err)
			}
			params = string(b)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE main.http_records SET raw_request = ?, request_authorization = ?, url = ?, path = ?, parameters = ?
			 WHERE uuid = ?`,
			rec.RawRequest, nullIfEmpty(rec.RequestAuthorization), rec.URL, rec.Path, params, rec.UUID); err != nil {
			return fmt.Errorf("store redacted request %s: %w", rec.UUID, err)
		}
	}
	if r.response {
		if _, err := tx.ExecContext(ctx,
			`UPDATE main.http_records SET raw_response = ?, response_hash = ?,
			 response_norm_hash = ?, response_words = ?, response_content_length = ? WHERE uuid = ?`,
			rec.RawResponse, nullIfEmpty(rec.ResponseHash),
			nullIfEmpty(rec.ResponseNormHash), rec.ResponseWords, rec.ResponseContentLength, rec.UUID); err != nil {
			return fmt.Errorf("store redacted response %s: %w", rec.UUID, err)
		}
	}
	return nil
}

// redactMergedFindingsTx redacts, inside a merge's transaction, the findings
// the merge inserted, and returns how many changed.
func redactMergedFindingsTx(ctx context.Context, tx *sql.Tx, ids []int64, extra map[string]struct{}) (int, error) {
	changed := 0
	for chunk := range slices.Chunk(ids, recordRedactPage) {
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		in := strings.TrimSuffix(strings.Repeat("?, ", len(chunk)), ", ")
		rows, err := tx.QueryContext(ctx,
			"SELECT id, request, response, additional_evidence FROM main.findings WHERE id IN ("+in+")", args...)
		if err != nil {
			return changed, fmt.Errorf("read findings to redact: %w", err)
		}
		var page []*Finding
		for rows.Next() {
			var (
				f                  Finding
				req, resp, extraEv sql.NullString
			)
			if err := rows.Scan(&f.ID, &req, &resp, &extraEv); err != nil {
				_ = rows.Close()
				return changed, fmt.Errorf("scan finding to redact: %w", err)
			}
			f.Request, f.Response = req.String, resp.String
			if extraEv.Valid && extraEv.String != "" {
				_ = json.Unmarshal([]byte(extraEv.String), &f.AdditionalEvidence)
			}
			page = append(page, &f)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return changed, fmt.Errorf("read findings to redact: %w", err)
		}
		for _, f := range page {
			if !RedactFindingCredentials(f, extra) {
				continue
			}
			var extraEv any
			if len(f.AdditionalEvidence) > 0 {
				b, err := json.Marshal(f.AdditionalEvidence)
				if err != nil {
					return changed, fmt.Errorf("encode redacted evidence: %w", err)
				}
				extraEv = string(b)
			}
			if _, err := tx.ExecContext(ctx,
				"UPDATE main.findings SET request = ?, response = ?, additional_evidence = ? WHERE id = ?",
				nullIfEmpty(f.Request), nullIfEmpty(f.Response), extraEv, f.ID); err != nil {
				return changed, fmt.Errorf("store redacted finding %d: %w", f.ID, err)
			}
			changed++
		}
	}
	return changed, nil
}
