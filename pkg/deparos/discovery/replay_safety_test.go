package discovery

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

func httpFact(method string) *jstangle.HTTPRequestFact {
	return &jstangle.HTTPRequestFact{
		Kind:   "httpRequest",
		Method: jstangle.ValueTemplate{Rendered: method, Static: true},
		Client: "fetch",
	}
}

func graphQLFact(op string) *jstangle.HTTPRequestFact {
	return &jstangle.HTTPRequestFact{
		Kind:          "httpRequest",
		Method:        jstangle.ValueTemplate{Rendered: "POST", Static: true},
		Client:        "graphql",
		OperationType: op,
	}
}

// TestReplaySafetyLadder locks in which recovered requests each safety level is
// allowed to actually send during discovery. The ladder is monotonic: anything a
// lower level permits, every higher level permits too.
func TestReplaySafetyLadder(t *testing.T) {
	cases := []struct {
		name string
		fact *jstangle.HTTPRequestFact
		// allowed under metadata-only, read-only, safe-baseline, state-changing
		want [4]bool
	}{
		{"GET", httpFact("GET"), [4]bool{false, true, true, true}},
		{"HEAD", httpFact("HEAD"), [4]bool{false, true, true, true}},
		{"OPTIONS", httpFact("OPTIONS"), [4]bool{false, true, true, true}},
		{"PUT idempotent write", httpFact("PUT"), [4]bool{false, false, true, true}},
		{"DELETE idempotent write", httpFact("DELETE"), [4]bool{false, false, true, true}},
		{"POST", httpFact("POST"), [4]bool{false, false, false, true}},
		{"PATCH", httpFact("PATCH"), [4]bool{false, false, false, true}},
		{"empty method defaults to GET", httpFact(""), [4]bool{false, true, true, true}},
		{"WS handshake never replayed", httpFact("WS"), [4]bool{false, false, false, false}},
		{"SSE handshake never replayed", httpFact("SSE"), [4]bool{false, false, false, false}},
		{"GraphQL query is read-only", graphQLFact("query"), [4]bool{false, true, true, true}},
		{"GraphQL mutation is state-changing", graphQLFact("mutation"), [4]bool{false, false, false, true}},
		{"GraphQL subscription treated as state-changing", graphQLFact("subscription"), [4]bool{false, false, false, true}},
		{"GraphQL unlabeled treated as state-changing", graphQLFact(""), [4]bool{false, false, false, true}},
	}
	levels := []ReplaySafety{ReplaySafetyMetadataOnly, ReplaySafetyReadOnly, ReplaySafetyBaseline, ReplaySafetyStateChanging}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i, level := range levels {
				if got := level.AllowsFact(tc.fact); got != tc.want[i] {
					t.Fatalf("level %d AllowsFact = %v, want %v", level, got, tc.want[i])
				}
			}
		})
	}
}

// TestParseReplaySafety proves the config parser fails closed: the default and
// any unknown/empty value resolve to the safe read-only policy.
func TestParseReplaySafety(t *testing.T) {
	cases := map[string]ReplaySafety{
		"metadata-only":  ReplaySafetyMetadataOnly,
		"read-only":      ReplaySafetyReadOnly,
		"safe-baseline":  ReplaySafetyBaseline,
		"state-changing": ReplaySafetyStateChanging,
		"STATE-CHANGING": ReplaySafetyStateChanging, // case-insensitive
		" read-only ":    ReplaySafetyReadOnly,       // trimmed
		"":               ReplaySafetyReadOnly,       // default fails closed
		"bogus":          ReplaySafetyReadOnly,       // unknown fails closed
	}
	for in, want := range cases {
		if got := ParseReplaySafety(in); got != want {
			t.Fatalf("ParseReplaySafety(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestReplaySafetyNilFactBlocked guards the nil path (defensive).
func TestReplaySafetyNilFactBlocked(t *testing.T) {
	if ReplaySafetyStateChanging.AllowsFact(nil) {
		t.Fatal("a nil fact must never be replayable")
	}
}
