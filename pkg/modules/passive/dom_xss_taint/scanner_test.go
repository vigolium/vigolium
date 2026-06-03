package dom_xss_taint

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/jsscan"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// requireBinary skips when the embedded jsscan binary isn't available (e.g. a
// fresh checkout before `make ensure-jsscan`).
func requireBinary(t *testing.T) {
	t.Helper()
	sc, err := jsscan.NewScanner(jsscan.DefaultConfig())
	if err != nil || sc.EnsureBinary() != nil {
		t.Skip("skipping: no valid jsscan binary available")
	}
}

func scan(t *testing.T, contentType, body string) int {
	t.Helper()
	rr := modtest.Request(t, "http://example.com/page")
	rr = modtest.Response(rr, contentType, body)
	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	return len(res)
}

func TestDomXssTaint_DetectsFlowInInlineScript(t *testing.T) {
	requireBinary(t)
	html := `<html><head><script>
		var x = location.hash;
		document.getElementById('out').innerHTML = x;
	</script></head><body></body></html>`
	if n := scan(t, "text/html", html); n == 0 {
		t.Fatal("expected a DOM-XSS taint finding for hash -> innerHTML")
	}
}

func TestDomXssTaint_NoFindingWhenSinkIsConstant(t *testing.T) {
	requireBinary(t)
	// Source and sink tokens both present (gate passes), but no data flow — the
	// precision improvement over the regex module.
	html := `<html><script>
		var x = location.hash;
		el.innerHTML = "<b>static</b>";
	</script></html>`
	if n := scan(t, "text/html", html); n != 0 {
		t.Fatalf("expected no finding when sink uses a constant, got %d", n)
	}
}

func TestDomXssTaint_AnalyzesJavaScriptResponse(t *testing.T) {
	requireBinary(t)
	js := `eval(decodeURIComponent(location.search));`
	if n := scan(t, "application/javascript", js); n == 0 {
		t.Fatal("expected a finding for a .js response with search -> eval")
	}
}

func TestDomXssTaint_IgnoresNonScriptResponses(t *testing.T) {
	// No need for the binary: the gate/extraction returns early.
	if n := scan(t, "application/json", `{"location.hash":"innerHTML eval"}`); n != 0 {
		t.Fatalf("JSON responses must be ignored, got %d", n)
	}
}

func TestDomXssTaint_GateSkipsWhenNoSink(t *testing.T) {
	html := `<html><script>var x = location.hash; console.log(x);</script></html>`
	if n := scan(t, "text/html", html); n != 0 {
		t.Fatalf("expected gate to skip when no sink token present, got %d", n)
	}
	// Sanity: the gate regexes behave as expected.
	if gateSinkRe.MatchString("console.log(x)") {
		t.Fatal("console.log should not match the sink gate")
	}
	if !strings.Contains("location.hash", "location") {
		t.Fatal("unreachable")
	}
}
