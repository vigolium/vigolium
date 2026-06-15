//go:build integration

package form

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestFillTextDrivesBlurGatedNextButton verifies that FillText fires the full
// user-like event sequence (focus → input → change → keyup → blur), not just
// input/change. Multi-step login/registration flows commonly enable the
// "Next/Continue" button only after the field validates on blur; a fill that
// never blurs leaves the button disabled and the flow stuck, so the next step
// (and its traffic) is never reached. This serves a page with exactly that
// pattern and asserts the button unlocks after a fill.
func TestFillTextDrivesBlurGatedNextButton(t *testing.T) {
	const page = `<!doctype html><html><body>
		<form>
			<input id="email" type="email" name="email">
			<button id="next" type="button" disabled>Next</button>
		</form>
		<script>
			var email = document.getElementById('email');
			var next = document.getElementById('next');
			// Enable Next only after the field is validated on blur — the gate a
			// plain .value + input/change fill never trips.
			email.addEventListener('blur', function () {
				if (email.value.indexOf('@') > -1) { next.disabled = false; }
			});
		</script>
	</body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	}))
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	p, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	if err := p.Navigate(server.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	emailEl, err := p.Element("#email")
	if err != nil {
		t.Fatalf("Element(#email): %v", err)
	}
	if err := FillText(emailEl, "crawler@example.com"); err != nil {
		t.Fatalf("FillText: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// The value must be set...
	if v, _ := p.Eval(`document.getElementById('email').value`); v != "crawler@example.com" {
		t.Errorf("email value = %v, want crawler@example.com", v)
	}
	// ...and the blur-gated Next button must now be enabled.
	disabled, err := p.Eval(`document.getElementById('next').disabled`)
	if err != nil {
		t.Fatalf("Eval(next.disabled): %v", err)
	}
	if d, ok := disabled.(bool); !ok || d {
		t.Fatalf("Next button still disabled after fill (blur/validation events did not fire): %v", disabled)
	}
}
