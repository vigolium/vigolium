// Package output defines the ResultEvent finding model emitted by every module
// and the handlers that format and deliver results. It supports the console,
// JSONL, and HTML output formats (the latter via an embedded ag-grid report
// template) and carries the metadata — severity, confidence, evidence, matched
// request/response — that the executor fills in before findings are stored or
// reported.
package output
