package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/piolium"
)

// -----------------------------------------------------------------------------
// Request validation: /api/agent/run/audit
//
// These cover only the synchronous validation surface — anything that would
// require launching the audit subprocess (and therefore a real `pi` binary +
// piolium extension) is left to the e2e/canary tier.
// -----------------------------------------------------------------------------

func TestHandleAgentAudit_BadJSON(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	req := httptest.NewRequest(http.MethodPost, "/api/agent/run/audit",
		strings.NewReader("{not-json"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed JSON, got %d", resp.StatusCode)
	}
}

func TestHandleAgentAudit_MissingSource(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "source") {
		t.Errorf("expected error to mention source, got: %s", body)
	}
}

func TestHandleAgentAudit_InvalidMode(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{
		"source": ".",
		"mode":   "ridiculous",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid mode, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "mode") {
		t.Errorf("expected error to mention mode, got: %s", body)
	}
}

func TestHandleAgentAudit_InvalidIntensity(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{
		"source":    ".",
		"intensity": "ludicrous",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid intensity, got %d body=%s", resp.StatusCode, body)
	}
}

// TestHandleAgentAudit_PiBinaryMissing_DriverPiolium covers the path
// where driver=piolium is requested but `pi` isn't on PATH. We blank PATH
// for the duration of the test so exec.LookPath("pi") fails
// deterministically. The handler should 503 because the caller asked
// specifically for piolium and that driver can't run.
func TestHandleAgentAudit_PiBinaryMissing_DriverPiolium(t *testing.T) {
	t.Setenv("PATH", "")

	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{
		"source": ".",
		"mode":   "lite",
		"driver": "piolium",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when pi is not in PATH for driver=piolium, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(strings.ToLower(string(body)), "pi cli not found") {
		t.Errorf("expected error to mention missing pi CLI, got: %s", body)
	}
}

// TestHandleAgentAudit_DriverBothMissingRuntimes proves that driver=both
// no longer hard-errors when one (or both) per-driver runtimes are
// unavailable. Validation surface accepts the request; the per-driver
// dispatch is responsible for surfacing missing-binary errors on the
// child runs while the other driver still runs. We blank PATH so
// neither pi nor any audit platform binary resolves — the request must
// still leave validation cleanly.
func TestHandleAgentAudit_DriverBothMissingRuntimes(t *testing.T) {
	t.Setenv("PATH", "")

	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	// Bogus source path makes the background goroutine fail fast at
	// source resolution, so the t.TempDir cleanup doesn't race against an
	// audit/pi subprocess writing to the session dir.
	bogusSource := filepath.Join(t.TempDir(), "definitely-not-a-source")

	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{
		"source": bogusSource,
		"mode":   "lite",
		"driver": "both",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	// Anything in the 4xx-or-5xx range here means we regressed back to the
	// old fail-fast behavior. The request should be accepted (202) — even
	// if the eventual run ends up "completed_with_errors" once the
	// dispatcher discovers neither binary resolves at exec time.
	if resp.StatusCode >= 400 {
		t.Errorf("driver=both must not block on missing per-driver runtimes, got %d body=%s",
			resp.StatusCode, body)
	}

	// Wait for the background goroutine to fail and persist status.
	if resp.StatusCode < 400 {
		var ack AgenticScanResponse
		if jerr := json.Unmarshal(body, &ack); jerr == nil && ack.AgenticScanUUID != "" {
			_ = pollAgentStatus(t, app, ack.AgenticScanUUID, 10*time.Second)
		}
	}
}

func TestHandleAgentAudit_InvalidDriver(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{
		"source": ".",
		"driver": "claude", // unsupported
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported driver, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "driver") {
		t.Errorf("expected error to mention driver, got: %s", body)
	}
}

// driver=both now uses per-driver skip-unsupported (not a shared-set
// restriction): a mode unknown to BOTH drivers is still a 400 typo
// guard, but a mode only one driver supports is accepted and skipped on
// the other driver's leg.
func TestHandleAgentAudit_DriverBothRejectsModeUnknownToBoth(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	// "smoke" is not an audit-pipeline mode for either audit or piolium.
	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{
		"source": ".",
		"mode":   "smoke",
		"driver": "both",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for mode unknown to both drivers, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(strings.ToLower(string(body)), "unknown audit mode") {
		t.Errorf("expected 'unknown audit mode' error, got: %s", body)
	}
}

// Under the per-driver-skip contract, a mode only one driver supports is
// NOT rejected on a multi-driver run — it is accepted and simply skipped
// on the leg that can't run it. refresh is audit-only; driver=both must
// accept it (audit runs it, piolium leg skips it).
func TestHandleAgentAudit_DriverBothAcceptsSingleDriverMode(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	bogusSource := filepath.Join(t.TempDir(), "definitely-not-a-source")
	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{
		"source": bogusSource,
		"mode":   "refresh",
		"driver": "both",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode == http.StatusBadRequest {
		t.Errorf("expected refresh accepted under driver=both (audit runs it, piolium skips), got 400 body=%s", body)
	}
	if resp.StatusCode < 400 {
		var ack AgenticScanResponse
		if jerr := json.Unmarshal(body, &ack); jerr == nil && ack.AgenticScanUUID != "" {
			_ = pollAgentStatus(t, app, ack.AgenticScanUUID, 10*time.Second)
		}
	}
}

// TestHandleAgentAudit_DriverAuditDriverAcceptsAuditDriverOnlyMode verifies that
// driver=audit accepts audit-only modes (longshot, reinvest, refresh)
// that driver=both rejects. Status will be 503 (binary missing) or 202
// (accepted then async-failed) depending on whether `make build-audit`
// has run — this test only checks the mode validator.
func TestHandleAgentAudit_DriverAuditDriverAcceptsAuditDriverOnlyMode(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	// Bogus source path makes the background goroutine fail fast at
	// source resolution, so the t.TempDir cleanup doesn't race against an
	// audit subprocess writing to the session dir. This test only
	// exercises the validation surface — the actual harness run is
	// covered separately.
	bogusSource := filepath.Join(t.TempDir(), "definitely-not-a-source")

	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{
		"source": bogusSource,
		"mode":   "longshot",
		"driver": "audit",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode == http.StatusBadRequest {
		t.Errorf("expected mode 'longshot' to be accepted under driver=audit, got 400 body=%s", body)
	}

	if resp.StatusCode < 400 {
		var ack AgenticScanResponse
		if jerr := json.Unmarshal(body, &ack); jerr == nil && ack.AgenticScanUUID != "" {
			_ = pollAgentStatus(t, app, ack.AgenticScanUUID, 10*time.Second)
		}
	}
}

// TestHandleAgentAudit_DefaultDriverIsAuto proves that an omitted
// `driver` resolves to "auto" (not "both") and is accepted by the
// validation surface. Like the driver=both missing-runtimes test, the
// request must leave validation cleanly (no 4xx); a missing piolium
// runtime is benign under auto since piolium only runs if audit fails.
func TestHandleAgentAudit_DefaultDriverIsAuto(t *testing.T) {
	t.Setenv("PATH", "")

	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	bogusSource := filepath.Join(t.TempDir(), "definitely-not-a-source")

	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{
		"source": bogusSource,
		"mode":   "lite",
		// driver omitted on purpose — must default to "auto".
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode >= 400 {
		t.Errorf("default driver (auto) must not block on missing runtimes, got %d body=%s",
			resp.StatusCode, body)
	}

	if resp.StatusCode < 400 {
		var ack AgenticScanResponse
		if jerr := json.Unmarshal(body, &ack); jerr == nil && ack.AgenticScanUUID != "" {
			_ = pollAgentStatus(t, app, ack.AgenticScanUUID, 10*time.Second)
		}
	}
}

// driver=auto uses the same per-driver skip-unsupported contract as
// driver=both: a mode unknown to BOTH drivers is a 400 typo guard.
func TestHandleAgentAudit_DriverAutoRejectsModeUnknownToBoth(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/audit", map[string]any{
		"source": ".",
		"mode":   "smoke",
		"driver": "auto",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for mode unknown to both drivers under driver=auto, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(strings.ToLower(string(body)), "unknown audit mode") {
		t.Errorf("expected 'unknown audit mode' error, got: %s", body)
	}
}

// TestPlmFlagsFromAuditRequest verifies that the AgentAuditRequest →
// piolium.PlmFlags handoff produces the same argv shape the CLI emits.
// piolium.PlmFlags.Args has its own unit coverage; this only checks the
// per-field plumbing on the request.
func TestPlmFlagsFromAuditRequest(t *testing.T) {
	tests := []struct {
		name string
		req  AgentAuditRequest
		want []string
	}{
		{
			name: "all-zero drops everything",
			req:  AgentAuditRequest{},
			want: nil,
		},
		{
			name: "scan-limit + scan-since",
			req: AgentAuditRequest{
				PlmScanLimit: 250,
				PlmScanSince: "60 days ago",
			},
			want: []string{"--plm-scan-limit", "250", "--plm-scan-since", "60 days ago"},
		},
		{
			name: "all longshot knobs",
			req: AgentAuditRequest{
				PlmLongshotLimit:   200,
				PlmLongshotTimeout: 10000,
				PlmLongshotLangs:   "python,go",
			},
			want: []string{
				"--plm-longshot-limit", "200",
				"--plm-longshot-timeout", "10000",
				"--plm-longshot-langs", "python,go",
			},
		},
		{
			name: "retries pair",
			req: AgentAuditRequest{
				PlmPhaseRetries:   2,
				PlmCommandRetries: 3,
			},
			want: []string{
				"--plm-phase-retries", "2",
				"--plm-command-retries", "3",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := piolium.PlmFlags{
				ScanLimit:       tc.req.PlmScanLimit,
				ScanSince:       tc.req.PlmScanSince,
				PhaseRetries:    tc.req.PlmPhaseRetries,
				CommandRetries:  tc.req.PlmCommandRetries,
				LongshotLimit:   tc.req.PlmLongshotLimit,
				LongshotTimeout: tc.req.PlmLongshotTimeout,
				LongshotLangs:   tc.req.PlmLongshotLangs,
			}.Args()
			if !slices.Equal(got, tc.want) {
				t.Errorf("PlmFlags.Args() = %v, want %v", got, tc.want)
			}
		})
	}
}
