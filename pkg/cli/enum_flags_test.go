package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A closed-value filter or selector given a typo is a usage error, not a
// filter that matched nothing or a selection that fell back to everything.
func TestSelectorTyposAreUsageErrors(t *testing.T) {
	st := seedC6Store(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	for name, args := range map[string][]string{
		"finding --severity":         {"finding", "--severity", "bogus", "-j"},
		"finding --sort":             {"finding", "--sort", "bogus", "-j"},
		"traffic --source":           {"traffic", "--source", "bogus", "-j"},
		"module ls --type":           {"module", "ls", "--type", "bogus", "-j"},
		"scan-url --module-tag":      {"scan-url", "-t", srv.URL + "/", "--module-tag", "zzzznotatag", "-j"},
		"scan-url -m":                {"scan-url", "-t", srv.URL + "/", "-m", "zzzznotamodule", "-j"},
		"scan -m (runner path)":      {"scan", "-t", srv.URL + "/", "-m", "zzzznotamodule", "--only", "dynamic-assessment", "-j"},
		"kit secret-scan --rule":     {"kit", "secret-scan", "--rule", "no.such.rule", "-j"},
		"agent query --provider":     {"agent", "query", "hi", "--provider", "bogus", "-j"},
		"fuzz --mode":                {"fuzz", srv.URL + "/FUZZ", "-p", "a", "--mode", "bogus", "-j"},
		"finding --severity in list": {"finding", "--severity", "high,bogus", "-j"},
	} {
		code, out, errOut := st.run(t, args...)
		if code != 2 || !strings.Contains(out, `"usage_error"`) {
			t.Errorf("%s: exit %d\n%s\n%s", name, code, out, errOut)
		}
	}
	for name, args := range map[string][]string{
		"known source with rows":   {"traffic", "--source", "scanner", "-j"},
		"severity shorthand":       {"finding", "--severity", "h,c", "-j"},
		"non-standard method hint": {"traffic", "--method", "PROPFIND", "-j"},
	} {
		if code, out, errOut := st.run(t, args...); code != 0 {
			t.Errorf("%s: exit %d\n%s\n%s", name, code, out, errOut)
		}
	}
}
