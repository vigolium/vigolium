package runner

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestPhase_EdgeBlockedMarksPartial: a phase whose traffic a WAF
// challenged ends partial with edge_blocked and names the host, and the
// coverage caveats say so — a blocked scan never reads "complete, 0 findings".
func TestPhase_EdgeBlockedMarksPartial(t *testing.T) {
	srv, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<title>Attention Required! | Cloudflare</title>"))
	})
	r, infra := preflightRunner(t)
	ctx := context.Background()

	clean := r.beginPhase(ctx, string(PhaseHeuristicsCheck), infra.httpRequester)
	if out := clean.finish(ctx, nil); out.State != database.PhaseCompleted {
		t.Fatalf("phase with no traffic = %s, want completed", out.State)
	}

	tracker := r.beginPhase(ctx, string(PhaseDynamicAssessment), infra.httpRequester)
	rr, err := httpmsg.GetRawRequestFromURL(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := infra.httpRequester.Execute(rr, vighttp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	resp.Close()
	out := tracker.finish(ctx, nil)

	if out.State != database.PhasePartial {
		t.Fatalf("state = %s, want partial", out.State)
	}
	if len(out.Reasons) != 1 || out.Reasons[0] != database.ReasonEdgeBlocked {
		t.Fatalf("reasons = %v, want [edge_blocked]", out.Reasons)
	}
	host := strings.Split(strings.TrimPrefix(srv.URL, "http://"), ":")[0]
	if len(out.BlockedHosts) != 1 || !strings.EqualFold(out.BlockedHosts[0], host) {
		t.Fatalf("blocked hosts = %v, want [%s]", out.BlockedHosts, host)
	}

	caveats := database.CoverageCaveats(database.ScanCompletion{Phases: []database.PhaseOutcome{out}}, map[string]int64{"m": 2})
	if len(caveats) != 2 || caveats[0].Code != database.ReasonEdgeBlocked || len(caveats[0].Hosts) != 1 ||
		caveats[1].Code != database.CaveatModuleErrors || caveats[1].Count != 2 {
		t.Fatalf("caveats = %+v", caveats)
	}
	if line := caveats[0].Line(); !strings.Contains(line, host) || !strings.Contains(line, "[edge_blocked]") {
		t.Fatalf("caveat line = %q", line)
	}

	// A later phase with no new blocks is not blamed for the earlier one.
	next := r.beginPhase(ctx, string(PhaseKnownIssueScan), infra.httpRequester)
	if out := next.finish(ctx, nil); out.State != database.PhaseCompleted {
		t.Fatalf("next phase = %s %v, want completed", out.State, out.Reasons)
	}
}
