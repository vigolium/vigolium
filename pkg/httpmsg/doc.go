// Package httpmsg is the HTTP request/response model that flows through the
// scan. It parses and serializes raw requests and responses, models the
// associated service (host/port/scheme), and extracts insertion points
// (query/path/header/cookie/body, including nested JSON and form fields) that
// active modules mutate to inject payloads. It is foundational: most other
// packages depend on it.
package httpmsg
