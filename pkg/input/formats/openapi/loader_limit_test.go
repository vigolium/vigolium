package openapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A spec URL that streams past MaxSpecBytes is refused, and the
// caller's client is the one used.
func TestLoadSpecWithClient_LimitAndClient(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := []byte(strings.Repeat("a", 1<<20))
		for i := 0; i < (MaxSpecBytes>>20)+2; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer big.Close()
	if _, _, err := LoadSpecWithClient(big.URL+"/spec.json", nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("oversized spec: err = %v, want a size error", err)
	}

	var used bool
	small := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"openapi":"3.0.0"}`))
	}))
	defer small.Close()
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		return http.DefaultTransport.RoundTrip(r)
	})}
	if _, _, err := LoadSpecWithClient(small.URL+"/spec.json", client); err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Error("the caller's client was not used")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
