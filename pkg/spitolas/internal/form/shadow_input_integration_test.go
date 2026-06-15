//go:build integration

package form

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestDetectAndFillShadowInputs covers A2: a login form rendered inside a web
// component's shadow root. The light-DOM detection sees nothing; the shadow pass
// must surface the fields, and the fill must reach them (re-resolved by their
// data-vgo-uid tag) so a design-system login/register form actually gets filled.
func TestDetectAndFillShadowInputs(t *testing.T) {
	const page = `<!doctype html><html><body>
		<x-login></x-login>
		<script>
			class XLogin extends HTMLElement {
				connectedCallback() {
					const sr = this.attachShadow({mode: 'open'});
					sr.innerHTML =
						'<input id="email" name="email" type="email">' +
						'<input id="website" name="site" type="url">' +
						'<input id="pwd" name="password" type="password">';
				}
			}
			customElements.define('x-login', XLogin);
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
	time.Sleep(100 * time.Millisecond)

	cfg, _ := config.New(server.URL)
	handler := NewHandler(cfg)

	inputs, err := handler.DetectInputs(p)
	if err != nil {
		t.Fatalf("DetectInputs: %v", err)
	}
	if len(inputs) != 3 {
		t.Fatalf("expected 3 shadow inputs detected, got %d", len(inputs))
	}

	handler.FillInputs(p, inputs)
	time.Sleep(80 * time.Millisecond)

	// Read the filled values back out of the shadow root and validate the form.
	read := func(id string) interface{} {
		v, _ := p.Eval(`document.querySelector('x-login').shadowRoot.getElementById('` + id + `').value`)
		return v
	}
	if v := read("email"); v != FixedEmail {
		t.Errorf("shadow email = %v, want FixedEmail %q", v, FixedEmail)
	}
	if v := read("pwd"); v != FixedPassword {
		t.Errorf("shadow password = %v, want FixedPassword %q", v, FixedPassword)
	}
	// The url field gets a format-valid value and validates in the browser.
	if v := read("website"); v != "https://example.com" {
		t.Errorf("shadow url = %v, want https://example.com", v)
	}
	if valid, _ := p.Eval(`document.querySelector('x-login').shadowRoot.getElementById('website').validity.valid`); valid != true {
		t.Errorf("shadow url field not valid after fill")
	}
}
