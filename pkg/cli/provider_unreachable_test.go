package cli

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A provider nothing listens on is reported at once as provider_unreachable
// (exit 1), even with --no-preflight, instead of being retried until the
// run's deadline.
func TestAgentProviderUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close() // now closed: connections are refused

	st := seedC6Store(t)
	cfg := filepath.Join(st.home, ".vigolium", "vigolium-configs.yaml")
	body := "agent:\n  olium:\n    provider: openai-compatible\n    custom_provider:\n      base_url: http://127.0.0.1:" + strconv.Itoa(port) + "/v1\n      model_id: test\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"agent", "query", "-p", "hello", "--no-preflight", "-j"},
		{"agent", "query", "-p", "hello", "-j"},
	} {
		start := time.Now()
		code, out, errOut := st.run(t, args...)
		if code != 1 || !strings.Contains(out, `"code":"provider_unreachable"`) {
			t.Fatalf("%v: exit %d\n%s\n%s", args, code, out, errOut)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Fatalf("%v took %s", args, d)
		}
	}
}
