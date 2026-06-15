//go:build integration

package form

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// serveHTML starts a one-page test server returning the given HTML for any path.
func serveHTML(t *testing.T, html string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	}))
}

// TestTypedInputsPassBrowserValidation models a traditional server-rendered
// (PHP/JSP) registration form mixing strict HTML5 typed inputs. With the old
// "a"/empty fallback the form fails client-side validation and never submits;
// the type-aware values must make every field — and the whole form — valid.
func TestTypedInputsPassBrowserValidation(t *testing.T) {
	const page = `<!doctype html><html><body>
		<form id="reg">
			<input id="website" type="url"   name="website" required>
			<input id="dob"     type="date"  name="dob" min="1990-01-01" max="2030-12-31" required>
			<input id="qty"     type="number" name="qty" min="1" max="10" required>
			<input id="fav"     type="color" name="fav">
			<input id="email"   type="email" name="email" required>
			<input id="user"    type="text"  name="username" required>
		</form>
	</body></html>`

	server := serveHTML(t, page)
	defer server.Close()

	b := setupFormBrowser(t, server.URL)
	p, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	if err := p.Navigate(server.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	// Before: the form is invalid (required fields empty), and a placeholder "a"
	// in the url field fails url validation — the exact gap type-aware fill closes.
	if _, err := p.Eval(`document.getElementById('website').value = 'a'`); err != nil {
		t.Fatalf("seed url: %v", err)
	}
	if valid, _ := p.Eval(`document.getElementById('website').validity.valid`); valid != false {
		t.Fatalf("url field with 'a' should be invalid, got valid=%v", valid)
	}
	if valid, _ := p.Eval(`document.getElementById('reg').checkValidity()`); valid != false {
		t.Fatalf("form should start invalid, got valid=%v", valid)
	}

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	handler := NewHandler(cfg)
	inputs, err := handler.DetectInputs(p)
	if err != nil {
		t.Fatalf("DetectInputs: %v", err)
	}
	if len(inputs) == 0 {
		t.Fatal("no inputs detected")
	}
	handler.FillInputs(p, inputs)
	time.Sleep(80 * time.Millisecond)

	// After: every strict field validates and the whole form is submittable.
	for _, id := range []string{"website", "dob", "qty", "fav", "email", "user"} {
		valid, err := p.Eval(`document.getElementById('` + id + `').validity.valid`)
		if err != nil {
			t.Fatalf("validity(%s): %v", id, err)
		}
		if valid != true {
			val, _ := p.Eval(`document.getElementById('` + id + `').value`)
			t.Errorf("field %s invalid after fill (value=%v)", id, val)
		}
	}
	if valid, _ := p.Eval(`document.getElementById('reg').checkValidity()`); valid != true {
		t.Errorf("form should be valid after type-aware fill, got valid=%v", valid)
	}
}

// TestFillTextFiresFullEventSequence asserts the user-like event sequence is
// dispatched (focus → input → change → keyup → blur). Frameworks (React/Angular/
// Aura) and validation gate the next step on these; missing any can stall a flow.
func TestFillTextFiresFullEventSequence(t *testing.T) {
	const page = `<!doctype html><html><body>
		<input id="f" type="text">
		<script>
			window.__events = [];
			['focus','input','change','keyup','blur'].forEach(function(ev){
				document.getElementById('f').addEventListener(ev, function(){ window.__events.push(ev); });
			});
		</script>
	</body></html>`

	server := serveHTML(t, page)
	defer server.Close()
	b := setupFormBrowser(t, server.URL)
	p, _ := b.NewPage()
	if err := p.Navigate(server.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	elem, err := p.Element("#f")
	if err != nil {
		t.Fatalf("Element: %v", err)
	}
	if err := FillText(elem, "hello"); err != nil {
		t.Fatalf("FillText: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	got, _ := p.Eval(`window.__events.join(',')`)
	fired, _ := got.(string)
	for _, want := range []string{"focus", "input", "change", "keyup", "blur"} {
		if !strings.Contains(fired, want) {
			t.Errorf("event %q not fired; sequence was %q", want, fired)
		}
	}
}

// TestFillDrivesInputEventGate covers the React/Angular pattern where the model
// updates on the input event and a control unlocks accordingly (distinct from
// the blur-gated case). The fill must trip it.
func TestFillDrivesInputEventGate(t *testing.T) {
	const page = `<!doctype html><html><body>
		<input id="email" type="email">
		<button id="next" disabled>Next</button>
		<script>
			var e = document.getElementById('email'), n = document.getElementById('next');
			e.addEventListener('input', function(){ n.disabled = (e.value.indexOf('@') < 0); });
		</script>
	</body></html>`

	server := serveHTML(t, page)
	defer server.Close()
	b := setupFormBrowser(t, server.URL)
	p, _ := b.NewPage()
	if err := p.Navigate(server.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	elem, _ := p.Element("#email")
	if err := FillText(elem, "crawler@example.com"); err != nil {
		t.Fatalf("FillText: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if disabled, _ := p.Eval(`document.getElementById('next').disabled`); disabled != false {
		t.Errorf("input-gated Next still disabled after fill (input event not registered)")
	}
}

// TestFillTextarea exercises the textarea branch of the native value setter
// (HTMLTextAreaElement.prototype) and value-with-special-characters escaping.
func TestFillTextarea(t *testing.T) {
	const page = `<!doctype html><html><body><textarea id="ta"></textarea></body></html>`
	server := serveHTML(t, page)
	defer server.Close()
	b := setupFormBrowser(t, server.URL)
	p, _ := b.NewPage()
	if err := p.Navigate(server.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	elem, _ := p.Element("#ta")
	val := `He said "O'Brien" \ <ok> & done`
	if err := FillText(elem, val); err != nil {
		t.Fatalf("FillText: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	got, _ := p.Eval(`document.getElementById('ta').value`)
	if got != val {
		t.Errorf("textarea value = %q, want %q", got, val)
	}
}
