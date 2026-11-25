package modtest

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/output"
)

// ProofReplay is what replaying a recipe observed.
type ProofReplay struct {
	// Holds is the oracle's verdict over the attack and control responses.
	Holds bool
	// Marker is the token substituted for output.MarkerPlaceholder.
	Marker string
	// AttackBody and ControlBody are the last round's bodies.
	AttackBody, ControlBody string
}

// ReplayProof sends a recipe the way a caller does — a fresh marker
// substituted everywhere, the attack and control through a plain net/http
// client, the oracle judged in code — so a module test proves its recipe
// reproduces, not merely that it validates. A baseline-record control and an
// oast_interaction oracle need a store or a collector and fail the test.
func ReplayProof(t testing.TB, r *output.ProofRecipe) ProofReplay {
	t.Helper()
	if r == nil {
		t.Fatal("modtest: nil proof recipe")
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("modtest: recipe does not validate: %v", err)
	}
	if r.Control.IsBaseline() {
		t.Fatal("modtest: ReplayProof cannot replay a baseline_record_uuid control")
	}
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	marker := "mk" + hex.EncodeToString(buf)
	put := func(s string) string { return strings.ReplaceAll(s, output.MarkerPlaceholder, marker) }

	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	type answer struct {
		status  int
		header  http.Header
		body    string
		elapsed time.Duration
	}
	send := func(method, url string, headers map[string]string, body string) answer {
		req, err := http.NewRequest(method, put(url), strings.NewReader(put(body)))
		if err != nil {
			t.Fatalf("modtest: build recipe request: %v", err)
		}
		for k, v := range headers {
			req.Header.Set(k, put(v))
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("modtest: send recipe request: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return answer{resp.StatusCode, resp.Header, string(b), time.Since(start)}
	}
	attack := func() answer { return send(r.Request.Method, r.Request.URL, r.Request.Headers, r.Request.Body) }
	control := func() answer { return send(r.Control.Method, r.Control.URL, r.Control.Headers, r.Control.Body) }

	o := r.Oracle
	value := put(o.Value)
	rounds := 1
	if o.Kind == output.ProofTimingDelta {
		rounds = o.Repeat
	}
	out := ProofReplay{Marker: marker, Holds: true}
	for range rounds {
		c := control()
		a := attack()
		out.AttackBody, out.ControlBody = a.body, c.body
		var holds bool
		switch o.Kind {
		case output.ProofBodyContains:
			holds = strings.Contains(a.body, value) && !strings.Contains(c.body, value)
		case output.ProofBodyAbsent:
			holds = !strings.Contains(a.body, value) && strings.Contains(c.body, value)
		case output.ProofStatusDiffers:
			holds = a.status != c.status
		case output.ProofHeaderContains:
			holds = strings.Contains(a.header.Get(o.Header), value) && !strings.Contains(c.header.Get(o.Header), value)
		case output.ProofTimingDelta:
			holds = (a.elapsed - c.elapsed).Milliseconds() >= o.MinDeltaMS
		default:
			t.Fatalf("modtest: ReplayProof cannot judge oracle %s", o.Kind)
		}
		if !holds {
			out.Holds = false
			return out
		}
	}
	return out
}
