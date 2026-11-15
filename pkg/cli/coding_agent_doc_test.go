package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// codingAgentDoc is the written contract for the CLI's machine output. It lives
// two directories up from this package.
const codingAgentDoc = "../../docs/coding-agent.md"

// TestCodingAgentDocEnvelopeExample checks the `-j` envelope example in
// docs/coding-agent.md against the envelope the code actually produces.
//
// It follows the usage_examples_parse_test.go precedent, and for the same
// reason: the example had rotted. It showed `{"project_uuid", "total",
// "offset", "limit", "findings"}` — the pre-envelope shape, with the row array
// under the per-command name that is no longer emitted by default and no
// `schema_version` at all. A consumer written from that document would have
// parsed nothing and had no version field to notice why.
//
// The assertion is deliberately one-directional: every key in the document must
// be a key the envelope can produce. The reverse would force the example to
// list every optional field, which is not what an example is for.
func TestCodingAgentDocEnvelopeExample(t *testing.T) {
	doc := readCodingAgentDoc(t)

	raw := fencedJSONUnder(t, doc, "### Query findings → Output shape")
	var documented map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &documented),
		"the envelope example must be valid JSON")

	produced := producedEnvelopeKeys(t)

	for key := range documented {
		assert.Contains(t, produced, key,
			"docs/coding-agent.md documents envelope key %q, which no -j command emits", key)
	}

	// The ones that make the document usable at all: the version a consumer
	// gates on, the success branch and document shape, the row array it parses,
	// and the scope flag that tells it whether a filter was applied.
	for _, must := range []string{"schema_version", "ok", "kind", "items", "project_scoped"} {
		assert.Contains(t, documented, must,
			"the documented envelope must show %q", must)
	}

	// The pre-envelope row name is gone from the default output. Documenting it
	// as if it were still there is the specific rot this test exists to catch.
	assert.NotContains(t, documented, "findings",
		"`findings` is a --json-legacy-keys alias, not the default row array; the example must show `items`")
}

// TestCodingAgentDocHasNoStaleInMemoryClaim: the stateless JSONL load and the
// --glob-db merge have used a scratch FILE since improvement-1/2 — an in-memory
// database could not hold a large export, and a merge of several never could.
// The document said "in-memory" long after that stopped being true, which
// matters because it is the sentence a reader uses to decide whether a 10 GB
// glob will fit in RAM.
func TestCodingAgentDocHasNoStaleInMemoryClaim(t *testing.T) {
	doc := readCodingAgentDoc(t)
	for i, line := range strings.Split(doc, "\n") {
		if !strings.Contains(line, "in-memory") {
			continue
		}
		// One mention survives on purpose: the sentence explaining that it USED
		// to be in-memory. Anything else is a live claim.
		assert.Contains(t, line, "was an in-memory database once",
			"docs/coding-agent.md:%d still claims a store is in-memory:\n\t%s", i+1, strings.TrimSpace(line))
	}
}

// readCodingAgentDoc loads the contract document, skipping the test when it is
// not reachable (a packaging context that ships the package without the docs
// tree) rather than failing for a reason that is not about the code.
func readCodingAgentDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(codingAgentDoc))
	if os.IsNotExist(err) {
		t.Skipf("%s not reachable from the package directory", codingAgentDoc)
	}
	require.NoError(t, err)
	return string(b)
}

// fencedJSONUnder returns the first ```json block following the given heading.
func fencedJSONUnder(t *testing.T, doc, heading string) string {
	t.Helper()
	_, after, found := strings.Cut(doc, heading)
	require.True(t, found, "heading %q not found in %s", heading, codingAgentDoc)

	_, after, found = strings.Cut(after, "```json\n")
	require.True(t, found, "no fenced json block under %q", heading)

	body, _, found := strings.Cut(after, "\n```")
	require.True(t, found, "unterminated json block under %q", heading)
	return body
}

// producedEnvelopeKeys is the key set a fully-populated envelope marshals to.
// Taken from the real encoder rather than from a hand-written list, so a field
// renamed in agent_envelope.go fails this test instead of silently diverging
// from the document.
func producedEnvelopeKeys(t *testing.T) map[string]bool {
	t.Helper()
	env := newMachineEnvelope(findingCmd, "findings", []map[string]any{{"id": 1}}, 39, 0, 100).
		WithProjectScope("00000000-0000-0000-defa-c01001000001").
		WithQuery("finding", "--id", "1")
	env.DBPath = "/tmp/db.sqlite"
	// Fields a command attaches rather than the envelope itself; the document
	// mentions them by name, so they belong in the produced set.
	env.With("output_budget", map[string]any{}).
		With("glob_sources", map[string]any{}).
		With("targets_not_scanned", []string{})

	raw, err := env.MarshalJSON()
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))

	keys := make(map[string]bool, len(m))
	for k := range m {
		keys[k] = true
	}
	return keys
}
