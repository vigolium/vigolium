package core

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// corroborationModuleID labels findings synthesized by the active-probe response
// observer (not a registered module — its Info is fully self-describing).
const corroborationModuleID = "sqli-error-corroboration"

// maxCorroborationBodyBytes caps the response body copied into a corroboration
// record so a pathological error page cannot bloat storage.
const maxCorroborationBodyBytes = 8192

// probeCorroboration collects database-error leaks observed in ANY active module's
// 5xx probe response, so evidence surfaced by a probe whose own module did not check
// for it (or whose insertion point the dedicated SQLi module never reached) is not
// discarded. Passive detectors run only on the clean baseline before active modules
// send anything, so this observer is the one place a probe-elicited error is seen.
// Deduped by (host, path, dbms); emitted once at phase end.
type probeCorroboration struct {
	mu   sync.Mutex
	seen map[string]struct{}
	hits []*output.ResultEvent
}

func newProbeCorroboration() *probeCorroboration {
	return &probeCorroboration{seen: make(map[string]struct{})}
}

// observeProbeResponse is the requester's response-observer sink. It runs on the
// request goroutine, so it stays cheap: one shared-catalog match over the
// already-5xx-gated body, then a deduped append. Emission is deferred to phase end.
func (e *Executor) observeProbeResponse(obs http.ObservedResponse) {
	if e.corroboration == nil {
		return
	}
	body := string(obs.Body)
	dbms, pattern, ok := modkit.MatchSQLError(body)
	if !ok || pattern == nil {
		return
	}
	// A request that itself carries the DBMS signature — a probe echoing a driver
	// name, or the app reflecting our payload verbatim — is not a server-generated
	// leak. Only an error the backend produced is evidence.
	if pattern.Match(obs.RequestRaw) {
		return
	}

	host := obs.Host
	path := obs.URL
	if u, err := url.Parse(obs.URL); err == nil && u != nil {
		path = u.Path
	}
	key := host + "|" + path + "|" + dbms

	// The heavy catalog sweep (MatchSQLError) already ran unlocked above. Only a
	// dedup-miss — the first probe to leak a given (host, path, dbms) — builds a
	// record, so one critical section covering the dedup claim + build + append is
	// simplest and effectively uncontended.
	e.corroboration.mu.Lock()
	defer e.corroboration.mu.Unlock()
	if _, dup := e.corroboration.seen[key]; dup {
		return
	}
	e.corroboration.seen[key] = struct{}{}

	evidence := strings.TrimSpace(pattern.FindString(body))
	rawResp := httpmsg.BuildRawResponse(obs.Status, map[string]string{"Content-Type": obs.ContentType}, truncateForRecord(body))

	e.corroboration.hits = append(e.corroboration.hits, &output.ResultEvent{
		ModuleID:      corroborationModuleID,
		RecordKind:    output.RecordKindObservation,
		EvidenceGrade: output.EvidenceGradeObservation,
		Host:          host,
		URL:           obs.URL,
		Matched:       obs.URL,
		Request:       string(obs.RequestRaw),
		Response:      string(rawResp),
		ExtractedResults: []string{
			fmt.Sprintf("DBMS: %s", dbms),
			"Matched: " + modkit.Truncate(evidence, 200),
			fmt.Sprintf("HTTP status: %d", obs.Status),
		},
		Info: output.Info{
			Name:        "Database Error Leaked to Malformed Probe",
			Description: "A scanner probe carrying injection metacharacters elicited a server-side database error: the application surfaced a DBMS error message in response to malformed input, a strong indicator of an unparameterized query (error-based SQL injection) at this endpoint. This is a corroboration lead harvested from probe traffic — the dedicated error-based SQLi module confirms the class with a controlled re-check; investigate this endpoint even when it did not.",
			Severity:    severity.Medium,
			Confidence:  severity.Tentative,
			Tags:        []string{"injection", "sqli", "corroboration", "information-disclosure", "database-error"},
		},
		Metadata: map[string]any{"dbms": dbms, "status_code": obs.Status, "source": "active-probe-corroboration"},
	})
}

// drainProbeCorroboration emits the collected corroboration observations. Called at
// phase end after every worker has exited (mirrors the passive BatchFlusher drain),
// so it never races the observer running on a live request goroutine.
func (e *Executor) drainProbeCorroboration(ctx context.Context) {
	if e.corroboration == nil {
		return
	}
	e.corroboration.mu.Lock()
	hits := e.corroboration.hits
	e.corroboration.hits = nil
	e.corroboration.mu.Unlock()

	for _, r := range hits {
		if !e.moduleFindingAllowed(r.ID(), corroborationModuleID) {
			continue
		}
		r.ModuleType = database.ModuleTypePassive
		r.FindingSource = database.FindingSourceDynamicAssessment
		e.emitResult(ctx, r, nil, nil)
	}
}

func truncateForRecord(s string) string {
	if len(s) <= maxCorroborationBodyBytes {
		return s
	}
	return s[:maxCorroborationBodyBytes] + "\n...[truncated]"
}
