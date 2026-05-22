// Package replay implements HTTP replay-with-mutation: take a baseline
// request, apply insertion-point mutations or a raw-request override,
// send the result, and return a baseline-vs-replay diff.
package replay

import (
	gohttp "net/http"
)

// DefaultExcerptCap clips response/request excerpts emitted in JSON. The
// hash and full length are reported alongside so callers can detect
// when they're looking at a truncated view.
const DefaultExcerptCap = 4 * 1024

// Mutation is one insertion-point payload override. Type is optional
// and only used to disambiguate when the same name exists in multiple
// positions (e.g. URL_PARAM + HEADER + JSON_PARAM).
type Mutation struct {
	Name    string `json:"name"`
	Type    string `json:"type,omitempty"`
	Payload string `json:"payload"`
}

// Options describes one replay. Network policy (cookie jar, proxy,
// timeout, TLS, redirect behaviour) is the caller's responsibility —
// the engine doesn't construct clients.
type Options struct {
	// BaselineRequest is the original raw HTTP request that mutations
	// are applied to and that the diff is computed against. Required.
	BaselineRequest []byte

	// BaselineResponse is the original raw HTTP response, used to
	// compute the baseline summary. When empty and BaselineRequest is
	// set, Do() synthesizes a baseline by sending the un-mutated
	// request first.
	BaselineResponse []byte

	// BaselineStatus / BaselineResponseTime are used when
	// BaselineResponse is non-empty so we can mirror the stored
	// record's status code and timing rather than re-deriving them.
	BaselineStatus       int
	BaselineResponseTime int64

	// Either Mutations or RawRequest must be set. Mutations applies
	// named insertion-point overrides; RawRequest replaces the baseline
	// request bytes verbatim.
	Mutations  []Mutation
	RawRequest []byte

	// Destination — used to reconstruct the URL we POST to. Hostname
	// is required when sending; Port=0 lets the scheme default decide.
	Scheme   string
	Hostname string
	Port     int

	// HeaderOverlay rewrites the header block of the request after
	// mutation. Case-insensitive replacement; appends if not present.
	HeaderOverlay map[string]string

	NoRedirects bool

	// Client is required.
	Client *gohttp.Client

	// ExcerptCap overrides the excerpt clip size. Zero = DefaultExcerptCap.
	ExcerptCap int
}

// Summary describes the response side of a single HTTP exchange.
//
// RawBody holds the full response body (capped by the engine's read
// limit) for callers that need to persist the bytes back somewhere —
// json:"-" keeps it out of agent-facing payloads since Excerpt covers
// the model's needs and RawBody can be megabytes.
type Summary struct {
	Status         int           `json:"status"`
	ResponseLen    int           `json:"response_length"`
	ContentHash    string        `json:"content_hash,omitempty"`
	ResponseTimeMs int64         `json:"response_time_ms"`
	Headers        gohttp.Header `json:"headers,omitempty"`
	Excerpt        string        `json:"excerpt,omitempty"`
	Truncated      bool          `json:"excerpt_truncated,omitempty"`
	Error          string        `json:"error,omitempty"`
	RawBody        []byte        `json:"-"`
}

// Diff captures the comparison between baseline and replay.
type Diff struct {
	StatusChanged   bool     `json:"status_changed"`
	LengthDelta     int      `json:"length_delta"`
	ContentChanged  bool     `json:"content_changed"`
	ReflectsPayload []string `json:"reflects_payload,omitempty"`
	BaselineStatus  int      `json:"baseline_status"`
	BaselineLen     int      `json:"baseline_length"`
	BaselineHash    string   `json:"baseline_content_hash,omitempty"`
	Interpretation  string   `json:"interpretation,omitempty"`
}

// Result is the complete output of a single replay.
//
// AdditionalGroups is non-zero when BuildRequestWithPayloads returned
// multiple non-conflicting mutation groups and we only sent the first.
// Unmatched lists insertion-point names that didn't resolve.
type Result struct {
	MutatedRequest      string   `json:"mutated_request"`
	MutatedRequestTrunc bool     `json:"mutated_request_truncated,omitempty"`
	Baseline            *Summary `json:"baseline"`
	Replay              *Summary `json:"replay"`
	Diff                *Diff    `json:"diff"`
	AdditionalGroups    int      `json:"additional_payload_groups,omitempty"`
	Unmatched           []string `json:"unmatched_mutations,omitempty"`
}
