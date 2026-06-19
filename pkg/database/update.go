package database

import (
	"context"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// RecordResponseUpdate contains response fields to update on an existing HTTP record.
// Used by the traffic --replay --in-replace feature.
type RecordResponseUpdate struct {
	StatusCode            int
	StatusPhrase          string
	ResponseHTTPVersion   string
	ResponseContentType   string
	ResponseContentLength int64
	RawResponse           []byte
	ResponseHash          string
	ResponseTimeMs        int64
}

// UpdateRecordResponse replaces the response fields of an existing HTTP record.
func (r *Repository) UpdateRecordResponse(ctx context.Context, uuid string, update *RecordResponseUpdate) error {
	result, err := r.db.NewUpdate().
		Model((*HTTPRecord)(nil)).
		Set("status_code = ?", update.StatusCode).
		Set("status_phrase = ?", update.StatusPhrase).
		Set("response_http_version = ?", update.ResponseHTTPVersion).
		Set("response_content_type = ?", update.ResponseContentType).
		Set("response_content_length = ?", update.ResponseContentLength).
		Set("raw_response = ?", update.RawResponse).
		Set("response_hash = ?", update.ResponseHash).
		Set("response_time_ms = ?", update.ResponseTimeMs).
		Set("has_response = ?", true).
		Set("received_at = ?", time.Now()).
		Where("uuid = ?", uuid).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update record response: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no record found with uuid %s", uuid)
	}
	return nil
}

// BackfillRecordResponse populates the response columns of an existing
// request-only http_record stub from a freshly fetched request/response,
// computing every response-derived field (content-type/length, hashes,
// normalized hash, word count, title) via the shared FromHttpRequestResponse
// converter so the backfilled row matches a normally-saved record.
//
// Discovery stores endpoints synthesized from a parsed OpenAPI/Swagger/Postman
// spec as request-only stubs (status 0, empty body); the executor then fetches
// each baseline to scan the endpoint, but without this the stub stays at
// status 0 with an empty response in the traffic view. The update is guarded on
// has_response = false so it only ever fills a genuine stub — it never clobbers
// a record that already captured a response, making it idempotent across the
// discovery and dynamic-assessment phases. An rr with no response is a no-op.
func (r *Repository) BackfillRecordResponse(ctx context.Context, uuid string, rr *httpmsg.HttpRequestResponse) error {
	if rr == nil || rr.Response() == nil {
		return nil
	}

	// The rr.Response() guard above already guarantees the converter populates
	// the response columns (HasResponse), so no post-convert recheck is needed.
	rec := &HTTPRecord{}
	if err := rec.FromHttpRequestResponse(rr); err != nil {
		return fmt.Errorf("backfill: convert record: %w", err)
	}

	_, err := r.db.NewUpdate().
		Model((*HTTPRecord)(nil)).
		Set("status_code = ?", rec.StatusCode).
		Set("response_http_version = ?", rec.ResponseHTTPVersion).
		Set("response_content_type = ?", rec.ResponseContentType).
		Set("response_content_length = ?", rec.ResponseContentLength).
		Set("raw_response = ?", rec.RawResponse).
		Set("response_hash = ?", rec.ResponseHash).
		Set("response_norm_hash = ?", rec.ResponseNormHash).
		Set("response_words = ?", rec.ResponseWords).
		Set("response_title = ?", rec.ResponseTitle).
		Set("has_response = ?", true).
		Set("received_at = ?", time.Now()).
		Where("uuid = ? AND has_response = ?", uuid, false).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("backfill record response: %w", err)
	}
	return nil
}
