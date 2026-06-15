//go:build integration

package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
)

// recordingWriter is an in-memory network.Writer that collects every captured
// request URL so a test can assert which URLs the crawl actually requested.
type recordingWriter struct {
	mu   sync.Mutex
	urls []string
}

func (w *recordingWriter) Write(entry *network.TrafficEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.urls = append(w.urls, entry.Request.URL)
	return nil
}

func (w *recordingWriter) Close() error { return nil }

func (w *recordingWriter) sawContaining(substr string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, u := range w.urls {
		if strings.Contains(u, substr) {
			return true
		}
	}
	return false
}

// loginCrawlOutcome is the subset of crawl stats the login-CTA tests assert on.
type loginCrawlOutcome struct {
	driven  bool
	ctaText string
	rec     *recordingWriter
}

// runLoginCrawl spins up the given mux as the target site and runs the browser
// crawler against it with production defaults (SPA settle / consent dismissal /
// login-CTA priming all on), returning what the login-CTA priming did plus the
// captured-URL recorder. SPASettleTimeout is shortened to keep the test brisk.
func runLoginCrawl(t *testing.T, mux *http.ServeMux) loginCrawlOutcome {
	t.Helper()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 0
	cfg.MaxDepth = 0
	cfg.MaxDuration = 60 * time.Second
	cfg.SPASettleTimeout = 5 * time.Second // defaults: DismissConsent/LoginCTAPriming on

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New crawler: %v", err)
	}
	rec := &recordingWriter{}
	c.SetWriter(rec)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := c.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return loginCrawlOutcome{
		driven:  result.Stats.LoginCTADriven,
		ctaText: result.Stats.LoginCTAText,
		rec:     rec,
	}
}

// authFlowMux wires the OAuth → IDP → vendor-login chain shared by several tests:
// /oauth2/authorize 302→ /idp/login (HTML) which fires its own /aura data XHR.
// The landing page itself is supplied by the caller via landingHTML.
func authFlowMux(landingHTML string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(landingHTML))
	})
	mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/idp/login?app=1&RelayState=xyz", http.StatusFound)
	})
	mux.HandleFunc("/idp/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body><h1>Vendor Login</h1>
			<script>fetch('/aura?r=0&other.DLG_PortalFooter.getCountryCode=1');</script>
		</body></html>`))
	})
	mux.HandleFunc("/aura", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	return mux
}

func assertAuthFlowCaptured(t *testing.T, out loginCrawlOutcome) {
	t.Helper()
	if !out.driven {
		t.Fatalf("expected LoginCTADriven=true (the login CTA should have been clicked)")
	}
	for _, want := range []string{"/oauth2/authorize", "/idp/login", "/aura"} {
		if !out.rec.sawContaining(want) {
			t.Errorf("auth-flow URL %q was not captured (login CTA flow was missed)", want)
		}
	}
}

// TestCrawlDrivesLoginCTAShadowButton reproduces the original missed-login-flow
// bug: an unauthenticated visit lands on a portal whose "Log on" button lives
// inside a web component's shadow root and, when clicked, kicks off an
// OAuth → IDP → vendor login chain whose destination page fires its own data XHR.
// A cookie-consent overlay sits on top. The crawler must dismiss the overlay,
// detect and click the shadow-DOM CTA, follow the chain, and let the destination
// XHR fire — so /oauth2/authorize, /idp/login, and /aura are captured.
func TestCrawlDrivesLoginCTAShadowButton(t *testing.T) {
	out := runLoginCrawl(t, authFlowMux(`<!doctype html><html><body>
		<div id="onetrust-banner-sdk" style="position:fixed;inset:0;z-index:9999;background:#fff">
			<button id="onetrust-accept-btn-handler">Accept All</button>
		</div>
		<x-portal></x-portal>
		<script>
			class XPortal extends HTMLElement {
				connectedCallback() {
					const sr = this.attachShadow({mode:'open'});
					const b = document.createElement('button');
					b.textContent = 'Log on';
					b.addEventListener('click', function() {
						location.href = '/oauth2/authorize?response_type=code&client_id=abc';
					});
					sr.appendChild(b);
				}
			}
			customElements.define('x-portal', XPortal);
		</script>
	</body></html>`))

	assertAuthFlowCaptured(t, out)
	if !strings.Contains(strings.ToLower(out.ctaText), "log on") {
		t.Errorf("LoginCTAText = %q, want it to contain %q", out.ctaText, "Log on")
	}
}

// TestCrawlDrivesLoginCTALightDOMHrefLink covers href-based detection: a plain
// light-DOM anchor whose *text* gives no login hint but whose href points at an
// auth endpoint must still be recognized and driven.
func TestCrawlDrivesLoginCTALightDOMHrefLink(t *testing.T) {
	out := runLoginCrawl(t, authFlowMux(`<!doctype html><html><body>
		<h1>Welcome</h1>
		<a id="enter" href="/oauth2/authorize?response_type=code&client_id=abc">Member area</a>
	</body></html>`))

	assertAuthFlowCaptured(t, out)
}

// TestCrawlDismissesConsentThenDrivesLoginCTA proves the consent step is what
// unblocks the flow: the "Log on" button starts hidden and is revealed only when
// the consent banner is accepted. If consent were not dismissed the button would
// stay invisible and score below threshold, so a driven flow here means the
// consent click happened first.
func TestCrawlDismissesConsentThenDrivesLoginCTA(t *testing.T) {
	out := runLoginCrawl(t, authFlowMux(`<!doctype html><html><body>
		<button id="onetrust-accept-btn-handler">Accept All</button>
		<button id="logon" style="display:none"
			onclick="location.href='/oauth2/authorize?response_type=code&client_id=abc'">Log on</button>
		<script>
			document.getElementById('onetrust-accept-btn-handler')
				.addEventListener('click', function(){
					document.getElementById('logon').style.display = 'block';
				});
		</script>
	</body></html>`))

	assertAuthFlowCaptured(t, out)
}

// TestCrawlSkipsLogoutControl is the negative guard: a logout control must never
// be mistaken for a login CTA and driven.
func TestCrawlSkipsLogoutControl(t *testing.T) {
	out := runLoginCrawl(t, authFlowMux(`<!doctype html><html><body>
		<button onclick="location.href='/logout'">Log out</button>
		<a href="/search?q=x">Search</a>
	</body></html>`))

	if out.driven {
		t.Errorf("LoginCTADriven=true, but the page has only a logout control — it must not be driven (text=%q)", out.ctaText)
	}
	if out.rec.sawContaining("/oauth2/authorize") {
		t.Errorf("the auth flow was entered from a page with no login CTA")
	}
}

// TestCrawlNoLoginCTA is the negative guard for an ordinary page with no login
// affordance at all: priming must find nothing and report not-driven.
func TestCrawlNoLoginCTA(t *testing.T) {
	out := runLoginCrawl(t, authFlowMux(`<!doctype html><html><body>
		<h1>Marketing page</h1>
		<button>Search</button>
		<a href="/about">About us</a>
	</body></html>`))

	if out.driven {
		t.Errorf("LoginCTADriven=true on a page with no login CTA (text=%q)", out.ctaText)
	}
}

// TestCrawlDrivesWebComponentDivCTA covers the web-component case (the myapp
// portal pattern): the real, clickable "Log on" is a plain <div> with a
// JS-attached click handler — not an <a>/<button>/[role=button] — and it sits
// alongside a non-interactive aria-hidden loading-skeleton <button>. The detector
// must skip the skeleton and pick the div (found via its short login text, not a
// standard interactive selector), and a synthetic click on it must bubble to the
// handler and drive the flow.
func TestCrawlDrivesWebComponentDivCTA(t *testing.T) {
	out := runLoginCrawl(t, authFlowMux(`<!doctype html><html><body>
		<x-portal></x-portal>
		<script>
			class XPortal extends HTMLElement {
				connectedCallback() {
					const sr = this.attachShadow({mode:'open'});
					// Loading-skeleton button that must be skipped.
					const skel = document.createElement('button');
					skel.setAttribute('aria-hidden', 'true');
					skel.textContent = 'Log on';
					sr.appendChild(skel);
					// The real clickable: a div with a JS click handler, no href/role.
					const d = document.createElement('div');
					d.textContent = 'Log on';
					d.style.cursor = 'pointer';
					d.addEventListener('click', function() {
						location.href = '/oauth2/authorize?response_type=code&client_id=abc';
					});
					sr.appendChild(d);
				}
			}
			customElements.define('x-portal', XPortal);
		</script>
	</body></html>`))

	// Navigation only happens if the div (not the handler-less aria-hidden skeleton)
	// was clicked, so capturing the flow proves the skeleton was skipped.
	assertAuthFlowCaptured(t, out)
}

// TestCrawlSkipsLoadingSkeletonCTA is the negative guard for the skeleton itself:
// an aria-hidden loading placeholder (no hydrated button yet) must be skipped by
// the login-CTA priming even though it is otherwise clickable. We assert only on
// the priming-specific signal (LoginCTADriven) — the generic crawl loop may still
// click the button on its own, which is fine and not what this test covers.
func TestCrawlSkipsLoadingSkeletonCTA(t *testing.T) {
	out := runLoginCrawl(t, authFlowMux(`<!doctype html><html><body>
		<button aria-hidden="true" onclick="location.href='/oauth2/authorize?response_type=code'">Log on</button>
	</body></html>`))

	if out.driven {
		t.Errorf("LoginCTADriven=true on an aria-hidden loading skeleton — priming must skip it (text=%q)", out.ctaText)
	}
}
