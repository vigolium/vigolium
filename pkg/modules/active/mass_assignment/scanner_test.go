package mass_assignment

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestToString(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"string value", "admin", `"admin"`},
		{"bool value", true, "true"},
		{"int value", 99, "99"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toString(tt.value)
			if got != tt.want {
				t.Errorf("toString(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	m := New()
	if m.ID() != ModuleID {
		t.Errorf("ID() = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name() = %q, want %q", m.Name(), ModuleName)
	}
	if m.IncludesBaseCanProcess() {
		t.Error("IncludesBaseCanProcess() should return false")
	}
}

func TestValueNewlyReflected(t *testing.T) {
	base := `{"username":"bob"}`
	if !valueNewlyReflected("role", "admin", `{"username":"bob","role":"admin"}`, base) {
		t.Error("the exact injected role value should be newly reflected")
	}
	if valueNewlyReflected("role", "admin", `{"username":"bob","role":"user"}`, base) {
		t.Error("a normalized/rejected role value must not count as acceptance")
	}
	if valueNewlyReflected("username", "bob", `{"username":"bob","role":"admin"}`, base) {
		t.Error("a value already present in baseline is not newly reflected")
	}
}

func TestIsRejected(t *testing.T) {
	if !isRejected(400, "") || !isRejected(422, "") {
		t.Error("400/422 should be treated as rejection")
	}
	if !isRejected(200, "Error: unknown field role") {
		t.Error("unknown field message should be treated as rejection")
	}
	if isRejected(200, `{"ok":true}`) {
		t.Error("clean 2xx must not be a rejection")
	}
}

// jsonPost builds a POST application/json request/response pair targeting rawURL,
// attaching baselineBody as the captured (un-injected) baseline response.
func jsonPost(t *testing.T, rawURL, reqBody, baselineBody string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr := modtest.RequestJSON(t, rawURL, reqBody)
	return modtest.Response(rr, "application/json", baselineBody)
}

// decodeBody returns the JSON object of a request body, or an empty map.
func decodeBody(r *http.Request) map[string]any {
	out := map[string]any{}
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &out)
	return out
}

func TestScanPerRequest_Differential(t *testing.T) {
	// /selective accepts known privilege fields (the vuln) but drops truly-unknown
	// fields like the canary — the genuine mass-assignment case.
	// /ignore always returns a fixed body regardless of input (server silently ignores
	// the injected field — the false positive we must NOT flag).
	// /mirror echoes the entire received body back (blind reflection — also not a real
	// finding, and the canary control must suppress it).
	// /reject refuses unknown fields with 400.
	allow := map[string]bool{
		"username": true, "role": true, "admin": true, "is_admin": true,
		"isAdmin": true, "permissions": true, "verified": true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/selective", func(w http.ResponseWriter, r *http.Request) {
		in := decodeBody(r)
		echo := map[string]any{}
		for k, v := range in {
			if allow[k] {
				echo[k] = v
			}
		}
		_ = json.NewEncoder(w).Encode(echo)
	})
	mux.HandleFunc("/ignore", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"status":"ok","username":"bob"}`)
	})
	mux.HandleFunc("/mirror", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(decodeBody(r))
	})
	mux.HandleFunc("/reject", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"unknown field"}`)
	})
	mux.HandleFunc("/normalize", func(w http.ResponseWriter, r *http.Request) {
		in := decodeBody(r)
		out := map[string]any{"username": in["username"]}
		if _, supplied := in["role"]; supplied {
			out["role"] = "user"
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := modtest.Requester(t)
	mod := New()

	t.Run("selective immediate accept is a candidate", func(t *testing.T) {
		rr := jsonPost(t, srv.URL+"/selective", `{"username":"bob"}`, `{"username":"bob"}`)
		res, err := mod.ScanPerRequest(rr, client, &modkit.ScanContext{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(res) == 0 {
			t.Fatal("expected a candidate when the server accepts the exact privilege value")
		}
		if res[0].RecordKind != output.RecordKindCandidate {
			t.Fatalf("immediate response without readback must be a candidate, got %q", res[0].RecordKind)
		}
		if !strings.Contains(res[0].FuzzingParameter, "role") && res[0].FuzzingParameter == "" {
			t.Errorf("unexpected fuzzing parameter: %q", res[0].FuzzingParameter)
		}
	})

	t.Run("normalized privilege value is NOT reported", func(t *testing.T) {
		rr := jsonPost(t, srv.URL+"/normalize", `{"username":"bob"}`, `{"username":"bob"}`)
		res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(res) != 0 {
			t.Fatalf("a key returned with a different value does not prove privilege assignment: %+v", res)
		}
	})

	t.Run("silently ignored field is NOT reported", func(t *testing.T) {
		rr := jsonPost(t, srv.URL+"/ignore", `{"username":"bob"}`, `{"status":"ok","username":"bob"}`)
		res, err := mod.ScanPerRequest(rr, client, &modkit.ScanContext{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(res) != 0 {
			t.Fatalf("expected no finding when server ignores the injected key, got %d", len(res))
		}
	})

	t.Run("blindly mirrored input is NOT reported", func(t *testing.T) {
		rr := jsonPost(t, srv.URL+"/mirror", `{"username":"bob"}`, `{"username":"bob"}`)
		res, err := mod.ScanPerRequest(rr, client, &modkit.ScanContext{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(res) != 0 {
			t.Fatalf("expected no finding when server reflects arbitrary input (canary control), got %d", len(res))
		}
	})

	t.Run("rejected unknown field is NOT reported", func(t *testing.T) {
		rr := jsonPost(t, srv.URL+"/reject", `{"username":"bob"}`, `{"username":"bob"}`)
		res, err := mod.ScanPerRequest(rr, client, &modkit.ScanContext{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(res) != 0 {
			t.Fatalf("expected no finding when server rejects unknown fields, got %d", len(res))
		}
	})
}

func TestScanPerRequest_PersistentReadbackIsFinding(t *testing.T) {
	state := map[string]any{"username": "bob"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPatch {
			for key, value := range decodeBody(r) {
				if key == "username" || key == "role" || key == "admin" || key == "is_admin" || key == "isAdmin" || key == "permissions" || key == "verified" {
					state[key] = value
				}
			}
		}
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer srv.Close()

	base := modtest.RequestJSON(t, srv.URL+"/profile", `{"username":"bob"}`)
	raw, err := httpmsg.SetMethod(base.Request().Raw(), http.MethodPatch)
	if err != nil {
		t.Fatalf("set method: %v", err)
	}
	rr := httpmsg.NewRequestResponseRaw(raw, base.Service())
	rr = modtest.Response(rr, "application/json", `{"username":"bob"}`)
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected one persistent mass-assignment finding, got %+v", res)
	}
	if res[0].RecordKind != output.RecordKindFinding || res[0].EvidenceGrade != output.EvidenceGradeImpact {
		t.Fatalf("persistent readback must be an impact finding, got kind=%q grade=%q", res[0].RecordKind, res[0].EvidenceGrade)
	}
}

// TestScanPerRequest_NaturalKeyVariance reproduces the reported false positive: an
// endpoint whose response ALWAYS carries a privilege-shaped word (here "level", in
// an SSR page's embedded state / feature-flag blob) that the captured baseline
// snapshot happened to lack — so the key looks "newly reflected" even though the
// server ignores the injected field and never reflects arbitrary input. The
// canary control passes (arbitrary fields are not echoed); the single-sample diff
// + newly-reflected check would flag it. The reflection-tracks-injection reconfirm
// sends a fresh no-key control, sees "level" present WITHOUT injection, and drops.
func TestScanPerRequest_NaturalKeyVariance(t *testing.T) {
	// Response embeds "level" in its own state on every request, regardless of input,
	// and does NOT echo arbitrary/unknown fields (so the canary control does not bail).
	const ssrBody = `{"status":"ok","username":"bob","state":{"level":3,"theme":"dark"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, ssrBody)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Baseline snapshot lacks "level" (captured before the flag / a stale render).
	rr := jsonPost(t, srv.URL+"/profile", `{"username":"bob"}`, `{"status":"ok","username":"bob"}`)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a privilege word that appears in a fresh no-key control (natural page content, not our injection) must not be reported, got %d: %+v", len(res), res)
	}
}
