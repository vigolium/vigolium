package command_injection_echo

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// echoArith matches the primary injected form `echo <LEFT>$((A+B))<RIGHT>`.
var echoArith = regexp.MustCompile(`echo ([A-Za-z]+)\$\(\((\d+)\+(\d+)\)\)([A-Za-z]+)`)

// exprArith matches the `expr` fallback `echo <LEFT>$(expr A + B)<RIGHT>`.
var exprArith = regexp.MustCompile(`echo ([A-Za-z]+)\$\(expr (\d+) \+ (\d+)\)([A-Za-z]+)`)

// pyArith matches the interpreter fallback `print('LEFT'+str(A+B)+'RIGHT')`.
var pyArith = regexp.MustCompile(`print\('([A-Za-z]+)'\+str\((\d+)\+(\d+)\)\+'([A-Za-z]+)'\)`)

// emulateShell mimics a vulnerable OS-command sink: if the parameter value
// contains one of the injected arithmetic forms, it "executes" it by emitting
// LEFT + (A+B) + RIGHT, exactly as a real shell's `echo` would.
func emulateShell(value string) string {
	for _, re := range []*regexp.Regexp{echoArith, exprArith, pyArith} {
		if mm := re.FindStringSubmatch(value); mm != nil {
			a, _ := strconv.Atoi(mm[2])
			b, _ := strconv.Atoi(mm[3])
			return mm[1] + strconv.Itoa(a+b) + mm[4]
		}
	}
	return ""
}

// TestScan_ResultsBased_Positive: a sink that evaluates the injected arithmetic
// is detected with Certain confidence.
func TestScan_ResultsBased_Positive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		// Emulate `system("ping " + cmd)`: echo the (executed) output back.
		if out := emulateShell(cmd); out != "" {
			_, _ = w.Write([]byte("<html>pinging " + out + " ...</html>"))
			return
		}
		_, _ = w.Write([]byte("<html>pinging host ...</html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/run?cmd=host")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	if res[0].FuzzingParameter != "cmd" {
		t.Errorf("FuzzingParameter = %q, want cmd", res[0].FuzzingParameter)
	}
	if res[0].Info.Confidence != severity.Certain {
		t.Errorf("Confidence = %v, want Certain", res[0].Info.Confidence)
	}
	if res[0].Info.Severity != severity.Critical {
		t.Errorf("Severity = %v, want Critical", res[0].Info.Severity)
	}
}

// TestScan_ResultsBased_ReflectionNoFP: a sink that merely REFLECTS the raw
// payload (no execution) must NOT be reported. The literal `$((A+B))` text never
// becomes the computed sum, so the unique needle never appears.
func TestScan_ResultsBased_ReflectionNoFP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		// Pure reflection — the classic XSS-style echo, not command execution.
		_, _ = w.Write([]byte("<html>you searched for: " + cmd + "</html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/search?cmd=hello")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 findings on pure reflection, got %d", len(res))
	}
}

// TestScan_ResultsBased_StaticNoFP: a static endpoint that ignores the parameter
// produces no finding.
func TestScan_ResultsBased_StaticNoFP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>welcome</html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?cmd=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 findings on static page, got %d", len(res))
	}
}
