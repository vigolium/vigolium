//go:build poc

package server

// M1 CORS reflect-origin PoC (white-box Go test, build tag: poc)
//
// Run from the repo root:
//
//	go test -v -tags=poc -run TestM1_CORSReflectOrigin ./pkg/server/
//
// What it proves:
//  1. A CORS preflight OPTIONS from an attacker origin receives
//     Access-Control-Allow-Origin: <attacker> + Access-Control-Allow-Credentials: true.
//  2. A credentialed GET from the same attacker origin receives the same headers,
//     permitting the browser to hand the full response body to the attacker script.
//  3. A second unrelated origin is also reflected — this is not a fixed allow-list.
//
// Exploitability nuances:
//   - Bearer-in-Authorization-header only (default deployment):
//     ACAO+ACAC=true does NOT auto-attach the Authorization header in a browser
//     credentialed fetch — the attacker JS must already have the token (e.g. from
//     localStorage). Impact is limited to unauthenticated endpoints (/health,
//     /server-info, /metrics) PLUS any deployment that uses cookies or --no-auth.
//   - Cookie-based auth or --no-auth mode:
//     Full credential bypass — any attacker page visited by a victim can silently
//     read every /api/* response, exfiltrating findings, HTTP records, agent data,
//     API keys, and project configuration.
//   - Default deployment ships with cors_allowed_origins="reflect-origin"
//     (internal/config/server.go:30) so EVERY fresh install is affected.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

const m1AttackerOrigin = "https://attacker.example"

// newM1App constructs the minimal Fiber app that mirrors a default vigolium
// server deployment (cors_allowed_origins = "reflect-origin", no auth).
// Only the CORS middleware and /health route are exercised — no DB required.
func newM1App(t *testing.T) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ServerHeader: "Vigolium-poc-test",
	})
	cfg := ServerConfig{
		CORSAllowedOrigins: "reflect-origin",
		NoAuth:             true,
	}
	// Handlers struct zero-value is safe for HandleHealth — it only calls c.JSON.
	handlers := &Handlers{
		startTime:          time.Now(),
		scanStates:         make(map[string]*scanState),
		scanQueues:         make(map[string]chan *queuedScan),
		agentHeavySem:      make(chan struct{}, 5),
		agentLightSem:      make(chan struct{}, 10),
		agenticScanStatus:  make(map[string]*AgenticScanStatusResponse),
		projectHeavyActive: make(map[string]int),
		agentCleanupStop:   make(chan struct{}),
		counts:             newCountCache(10 * time.Second),
	}
	registerRoutes(app, handlers, cfg)
	return app
}

func m1Request(t *testing.T, app *fiber.App, method, path string, headers map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("app.Test %s %s: %v", method, path, err)
	}
	return resp
}

func TestM1_CORSReflectOrigin(t *testing.T) {
	app := newM1App(t)

	t.Log("=== M1 CORS reflect-origin PoC ===")
	t.Logf("Attacker origin : %s", m1AttackerOrigin)
	t.Logf("Code path       : pkg/server/routes.go:38-40")
	t.Logf("Default config  : internal/config/server.go:30 (reflect-origin)")

	// ── Step 1: CORS preflight (OPTIONS) ─────────────────────────────────────
	t.Log("[1] CORS preflight OPTIONS /health ...")
	preflightResp := m1Request(t, app, http.MethodOptions, "/health", map[string]string{
		"Origin":                         m1AttackerOrigin,
		"Access-Control-Request-Method":  "GET",
		"Access-Control-Request-Headers": "Authorization",
	})
	defer preflightResp.Body.Close()

	preflightACAO := preflightResp.Header.Get("Access-Control-Allow-Origin")
	preflightACAC := preflightResp.Header.Get("Access-Control-Allow-Credentials")
	t.Logf("  status : %d", preflightResp.StatusCode)
	t.Logf("  ACAO   : %q", preflightACAO)
	t.Logf("  ACAC   : %q", preflightACAC)

	if preflightACAO != m1AttackerOrigin {
		t.Errorf("preflight ACAO: want %q, got %q", m1AttackerOrigin, preflightACAO)
	}
	if !strings.EqualFold(preflightACAC, "true") {
		t.Errorf("preflight ACAC: want \"true\", got %q", preflightACAC)
	}

	// ── Step 2: Credentialed actual GET ───────────────────────────────────────
	t.Log("[2] Credentialed cross-origin GET /health ...")
	actualResp := m1Request(t, app, http.MethodGet, "/health", map[string]string{
		"Origin": m1AttackerOrigin,
	})
	defer actualResp.Body.Close()

	actualACAO := actualResp.Header.Get("Access-Control-Allow-Origin")
	actualACAC := actualResp.Header.Get("Access-Control-Allow-Credentials")
	body, _ := io.ReadAll(actualResp.Body)
	bodyStr := string(body)

	t.Logf("  status : %d", actualResp.StatusCode)
	t.Logf("  ACAO   : %q", actualACAO)
	t.Logf("  ACAC   : %q", actualACAC)
	t.Logf("  body   : %s", bodyStr)

	if actualACAO != m1AttackerOrigin {
		t.Errorf("actual GET ACAO: want %q, got %q", m1AttackerOrigin, actualACAO)
	}
	if !strings.EqualFold(actualACAC, "true") {
		t.Errorf("actual GET ACAC: want \"true\", got %q", actualACAC)
	}

	// ── Step 3: Second unrelated origin is also reflected ────────────────────
	t.Log("[3] Verifying reflection with a second origin (https://another-attacker.io) ...")
	secondResp := m1Request(t, app, http.MethodGet, "/health", map[string]string{
		"Origin": "https://another-attacker.io",
	})
	defer secondResp.Body.Close()
	secondACAO := secondResp.Header.Get("Access-Control-Allow-Origin")
	t.Logf("  second-origin ACAO: %q", secondACAO)
	if secondACAO != "https://another-attacker.io" {
		t.Errorf("second-origin ACAO: want reflection, got %q", secondACAO)
	}

	// ── Step 4: Exploitability notes ──────────────────────────────────────────
	t.Log("")
	t.Log("=== Exploitability Assessment ===")
	t.Log("FULL-RISK  : cookie auth, --no-auth, or any deployment where the browser")
	t.Log("             auto-sends credentials — attacker page reads all /api/* responses.")
	t.Log("LIMITED    : Bearer-only auth — browser does NOT auto-attach Authorization;")
	t.Log("             attacker needs the token from localStorage.  Public endpoints")
	t.Log("             (/health, /server-info, /metrics) are readable with no token.")
	t.Log("DEFAULT    : cors_allowed_origins='reflect-origin' in every fresh install")
	t.Log("             (internal/config/server.go:30) — ALL deployments affected.")

	// ── Step 5: Write evidence JSON ───────────────────────────────────────────
	confirmed := actualACAO == m1AttackerOrigin && strings.EqualFold(actualACAC, "true")
	status := "confirmed"
	if !confirmed {
		status = "failed"
	}

	evidenceResult := map[string]any{
		"status": status,
		"evidence": "Access-Control-Allow-Origin: " + actualACAO +
			" AND Access-Control-Allow-Credentials: " + actualACAC +
			" on GET /health with Origin: " + m1AttackerOrigin,
		"notes": "Default deployment (internal/config/server.go:30) ships with" +
			" reflect-origin. Bearer-only auth limits browser auto-attach but" +
			" ACAO+ACAC=true remains exploitable when attacker has token or" +
			" when running --no-auth / cookie auth. All public endpoints" +
			" (/health /server-info /metrics) readable cross-origin unconditionally.",
		"preflight_acao":     preflightACAO,
		"preflight_acac":     preflightACAC,
		"actual_acao":        actualACAO,
		"actual_acac":        actualACAC,
		"second_origin_acao": secondACAO,
		"response_body":      bodyStr,
	}

	evidenceDir := filepath.Join(
		"archon", "findings", "M1-cors-reflect-origin", "evidence",
	)
	if err := os.MkdirAll(evidenceDir, 0o755); err == nil {
		outBytes, _ := json.MarshalIndent(evidenceResult, "", "  ")
		outPath := filepath.Join(evidenceDir, "go-test-output.json")
		if writeErr := os.WriteFile(outPath, outBytes, 0o644); writeErr == nil {
			t.Logf("[*] Evidence written to %s", outPath)
		}
	}

	// Final structured output line — poc-executor parses this line.
	t.Logf(`{"status": %q, "evidence": "Access-Control-Allow-Origin: %s AND Access-Control-Allow-Credentials: true — credentialed cross-origin read confirmed on GET /health", "notes": "Default deployment affected; routes.go:38-40 + internal/config/server.go:30"}`,
		status, actualACAO)

	if !confirmed {
		t.Fatal("CORS reflect-origin misconfiguration NOT confirmed")
	}
	t.Log("=== VERDICT: CONFIRMED ===")
}
