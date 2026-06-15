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

func TestKeyNewlyReflected(t *testing.T) {
	base := `{"username":"bob"}`
	if !keyNewlyReflected("role", `{"username":"bob","role":"admin"}`, base) {
		t.Error("role injected into response but not baseline should be newly reflected")
	}
	if keyNewlyReflected("username", `{"username":"bob","role":"admin"}`, base) {
		t.Error("username present in baseline must not count as newly reflected")
	}
	if keyNewlyReflected("role", base, base) {
		t.Error("role absent from injected response is not reflected")
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
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := modtest.Requester(t)
	mod := New()

	t.Run("selective accept is reported", func(t *testing.T) {
		rr := jsonPost(t, srv.URL+"/selective", `{"username":"bob"}`, `{"username":"bob"}`)
		res, err := mod.ScanPerRequest(rr, client, &modkit.ScanContext{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(res) == 0 {
			t.Fatal("expected a finding when the server accepts and reflects a privilege key")
		}
		if !strings.Contains(res[0].FuzzingParameter, "role") && res[0].FuzzingParameter == "" {
			t.Errorf("unexpected fuzzing parameter: %q", res[0].FuzzingParameter)
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
