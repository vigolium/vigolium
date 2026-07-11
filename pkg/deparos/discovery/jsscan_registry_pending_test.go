package discovery

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

// TestPendingLen_TracksUndrainedFacts backs the end-of-scan JS replay flush:
// PendingLen must report facts registered after the last drain (the tail-bundle
// race) and return to zero once replayed, so tryFlushPendingJSReplay schedules
// exactly the rounds it needs and then stops.
func TestPendingLen_TracksUndrainedFacts(t *testing.T) {
	reg := NewRequestTemplateRegistry()

	if got := reg.PendingLen(); got != 0 {
		t.Fatalf("fresh registry PendingLen = %d, want 0", got)
	}

	mkFact := func(path string) jstangle.HTTPRequestFact {
		return jstangle.HTTPRequestFact{
			Kind:       "httpRequest",
			URL:        jstangle.ValueTemplate{Rendered: path, Static: true},
			Method:     jstangle.ValueTemplate{Rendered: "GET", Static: true},
			Provenance: jstangle.Provenance{Extractor: "test", Confidence: "high"},
		}
	}

	// First bundle registers two facts.
	reg.Add("https://app.example.com/a.js", mkFact("/api/users"))
	reg.Add("https://app.example.com/a.js", mkFact("/api/orders"))
	if got := reg.PendingLen(); got != 2 {
		t.Fatalf("after 2 adds PendingLen = %d, want 2", got)
	}

	// A replay drains the pending set.
	drained := reg.PendingReplay()
	if len(drained) != 2 {
		t.Fatalf("PendingReplay returned %d, want 2", len(drained))
	}
	if got := reg.PendingLen(); got != 0 {
		t.Fatalf("after drain PendingLen = %d, want 0", got)
	}

	// Simulate a slow tail bundle registering a fact AFTER the drain — this is
	// exactly what the flush must catch.
	reg.Add("https://app.example.com/tail.js", mkFact("/api/late"))
	if got := reg.PendingLen(); got != 1 {
		t.Fatalf("tail-bundle fact PendingLen = %d, want 1", got)
	}

	reg.PendingReplay()
	if got := reg.PendingLen(); got != 0 {
		t.Fatalf("after final drain PendingLen = %d, want 0", got)
	}
}

// TestRequeue_ReturnsClaimedTemplateToPending backs the non-destructive-claim
// half of the replay fix: PendingReplay claims destructively (deletes on read,
// before the request is sent), so a template whose replay fails to send must be
// returned to pending via Requeue for a flush round to retry — rather than being
// silently consumed.
func TestRequeue_ReturnsClaimedTemplateToPending(t *testing.T) {
	reg := NewRequestTemplateRegistry()
	const src = "https://app.example.com/a.js"
	reg.Add(src, jstangle.HTTPRequestFact{
		Kind:       "httpRequest",
		URL:        jstangle.ValueTemplate{Rendered: "/api/users", Static: true},
		Method:     jstangle.ValueTemplate{Rendered: "GET", Static: true},
		Provenance: jstangle.Provenance{Extractor: "test", Confidence: "high"},
	})

	// Claim (destructive): pending drains to zero, but the template body survives
	// in items so it can be requeued by id.
	drained := reg.PendingReplay()
	if len(drained) != 1 {
		t.Fatalf("PendingReplay drained %d, want 1", len(drained))
	}
	if got := reg.PendingLen(); got != 0 {
		t.Fatalf("after claim PendingLen = %d, want 0", got)
	}
	id := drained[0].ID

	// A simulated send failure requeues the claimed template.
	if !reg.Requeue(src, id) {
		t.Fatal("Requeue of a claimed template must succeed")
	}
	if got := reg.PendingLen(); got != 1 {
		t.Fatalf("after requeue PendingLen = %d, want 1", got)
	}

	// Unknown / blank ids are no-ops (already-evicted work, or non-registry
	// variants that carry no template id).
	if reg.Requeue(src, "does-not-exist") {
		t.Fatal("Requeue of an unknown id must be a no-op")
	}
	if reg.Requeue(src, "") {
		t.Fatal("Requeue with a blank id must be a no-op")
	}
	if got := reg.PendingLen(); got != 1 {
		t.Fatalf("no-op requeues changed PendingLen to %d, want 1", got)
	}

	// The requeued template drains again — the retry round the flush schedules.
	again := reg.PendingReplay()
	if len(again) != 1 || again[0].ID != id {
		t.Fatalf("requeued template did not drain on retry: %+v", again)
	}
}
