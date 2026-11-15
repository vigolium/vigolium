package cli

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// `server -j` prints exactly one server.ready line on stdout once it is
// bound, logs to stderr, records a pidfile; `server status` sees it and
// `server stop` stops it.
func TestServerMachineModeStatusStop(t *testing.T) {
	st := seedC6Store(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	full := []string{"--db", st.db, "server", "-A", "--host", "127.0.0.1", "--service-port", itoa(int64(port)), "-j"}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFindingLifecycleChild$", "-test.v=false")
	env := []string{c6ChildEnv + "=" + strings.Join(full, "\x1f"), "HOME=" + st.home, "NO_COLOR=1"}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "HOME=") && !strings.HasPrefix(kv, "VIGOLIUM_") {
			env = append(env, kv)
		}
	}
	cmd.Env = env
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	// Drain stdout, then reap the child, so an exited server is not left a
	// zombie that still looks alive to `server stop`.
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
		_ = cmd.Wait()
	}()
	var ready map[string]any
	select {
	case line := <-lines:
		if err := json.Unmarshal([]byte(line), &ready); err != nil {
			t.Fatalf("first stdout line is not JSON: %q", line)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no server.ready line")
	}
	if ready["type"] != "server.ready" || ready["auth"] != "none" || int(ready["pid"].(float64)) != cmd.Process.Pid {
		t.Fatalf("server.ready = %v", ready)
	}

	code, out, errOut := st.run(t, "server", "status", "-j")
	if code != 0 || !strings.Contains(out, `"running":true`) || !strings.Contains(out, `"health_pid_matches":true`) {
		t.Fatalf("server status: exit %d\n%s\n%s", code, out, errOut)
	}
	code, out, errOut = st.run(t, "server", "stop", "--port", itoa(int64(port)), "-j")
	if code != 0 || !strings.Contains(out, `"stopped":true`) {
		t.Fatalf("server stop: exit %d\n%s\n%s", code, out, errOut)
	}
	// Nothing else reached stdout: the access log and banner went to stderr.
	for line := range lines {
		t.Fatalf("extra stdout line after server.ready: %q", line)
	}
	if _, err := os.Stat(serverPidPathIn(st.home, port)); !os.IsNotExist(err) {
		t.Fatalf("pidfile left after a clean stop: %v", err)
	}
	if code, out, _ := st.run(t, "server", "stop", "--port", itoa(int64(port)), "-j"); code != 1 {
		t.Fatalf("server stop with no server: exit %d\n%s", code, out)
	}
}

func serverPidPathIn(home string, port int) string {
	return home + "/.vigolium/server/" + itoa(int64(port)) + ".json"
}
