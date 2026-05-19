package database

import (
	"context"
	"fmt"
	"time"
)

// RecordResponseUpdate contains response fields to update on an existing HTTP record.
// Used by the traffic replay --in-replace feature.
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
