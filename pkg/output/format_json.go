package output

import (
	jsoniter "github.com/json-iterator/go"
)

// formatJSON formats the output for json based formatting.
//
// When the response is to be excluded from output it serializes a shallow COPY
// with Response cleared, never the caller's event. The same *ResultEvent is
// frequently written to output and then persisted to the database (e.g. the
// known-issue scan callback writes before SaveFinding/SaveRecord run) — zeroing
// Response on the original here would wipe the response body from the stored
// finding and its HTTP record too.
func (w *StandardWriter) formatJSON(output *ResultEvent) ([]byte, error) {
	if !w.IncludeResponseInOutput && output.Response != "" {
		clone := *output
		clone.Response = ""
		return jsoniter.Marshal(&clone)
	}
	return jsoniter.Marshal(output)
}
