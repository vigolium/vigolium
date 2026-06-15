//go:build integration

package browser

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

const shadowPage = `<!doctype html><html><body>
	<x-login></x-login>
	<script>
		window.__clicked = false;
		class XLogin extends HTMLElement {
			connectedCallback() {
				const sr = this.attachShadow({mode: 'open'});
				sr.innerHTML = '<button id="go">Go</button>' +
					'<input id="email" type="email">';
				sr.getElementById('go').addEventListener('click', () => { window.__clicked = true; });
			}
		}
		customElements.define('x-login', XLogin);
	</script>
</body></html>`

func shadowServerPage(t *testing.T) (*httptest.Server, *Page) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(shadowPage))
	}))
	cfg, err := config.New(server.URL)
	if err != nil {
		server.Close()
		t.Fatalf("config: %v", err)
	}
	cfg.Headless = true
	b, err := New(cfg)
	if err != nil {
		server.Close()
		t.Fatalf("browser: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	p, err := b.NewPage()
	if err != nil {
		server.Close()
		t.Fatalf("page: %v", err)
	}
	if err := p.Navigate(server.URL); err != nil {
		server.Close()
		t.Fatalf("navigate: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // let the component upgrade + attach shadow
	return server, p
}

// TestShadowElementsClickRoundTrip is the end-to-end A1 mechanism: a clickable
// inside a shadow root is invisible to a light-DOM query, but ShadowElements
// finds and tags it, and Element re-resolves the tag (shadow-piercing fallback)
// so it can be clicked.
func TestShadowElementsClickRoundTrip(t *testing.T) {
	server, p := shadowServerPage(t)
	defer server.Close()

	// Light DOM sees no button (it's in the shadow root) — proves the gap.
	if light, _ := p.Elements("button"); len(light) != 0 {
		t.Fatalf("expected 0 light-DOM buttons, got %d", len(light))
	}

	// ShadowElements finds and tags it.
	btns, err := p.ShadowElements("button")
	if err != nil {
		t.Fatalf("ShadowElements: %v", err)
	}
	if len(btns) != 1 {
		t.Fatalf("expected 1 shadow button, got %d", len(btns))
	}
	uid, _ := btns[0].Attribute("data-vgo-uid")
	if uid == "" || uid == "<nil>" {
		t.Fatalf("shadow button not tagged with data-vgo-uid (got %q)", uid)
	}

	// Element re-resolves the shadow tag and the click reaches the shadow handler.
	sel := `[data-vgo-uid="` + uid + `"]`
	el, err := p.Element(sel)
	if err != nil || el == nil {
		t.Fatalf("Element failed to re-resolve shadow tag %s: %v", sel, err)
	}
	if err := el.Click(); err != nil {
		t.Fatalf("click: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if clicked, _ := p.Eval(`window.__clicked`); clicked != true {
		t.Errorf("shadow button click had no effect (clicked=%v)", clicked)
	}
}

// TestShadowElementsFindsInput confirms inputs inside shadow roots are surfaced
// (and tagged) too — the basis for filling shadow-DOM forms.
func TestShadowElementsFindsInput(t *testing.T) {
	server, p := shadowServerPage(t)
	defer server.Close()

	if light, _ := p.Elements("input"); len(light) != 0 {
		t.Fatalf("expected 0 light-DOM inputs, got %d", len(light))
	}
	inputs, err := p.ShadowElements("input,textarea,select")
	if err != nil {
		t.Fatalf("ShadowElements: %v", err)
	}
	if len(inputs) != 1 {
		t.Fatalf("expected 1 shadow input, got %d", len(inputs))
	}
	if uid, _ := inputs[0].Attribute("data-vgo-uid"); uid == "" || uid == "<nil>" {
		t.Fatalf("shadow input not tagged")
	}
}
