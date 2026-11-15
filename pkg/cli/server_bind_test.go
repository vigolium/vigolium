package cli

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A taken port is exit 1 before anything announces the server.
func TestServerBindFailureExitsOne(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	e := newB5Env(t)
	code, stdout, stderr := e.runChildWithin(t, 60*time.Second, "server", "--host", "127.0.0.1", "--service-port", port)
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	require.NotContains(t, stdout, "Server running")
	require.Contains(t, stderr, "address already in use")
}

// --no-auth on a routable --host is refused (exit 2) before anything binds.
func TestServerRefusesUnauthenticatedPublicBind(t *testing.T) {
	e := newB5Env(t)
	code, stdout, stderr := e.runChildWithin(t, 60*time.Second, "server", "--host", "0.0.0.0", "--service-port", "0", "-A")
	require.Equal(t, 2, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	require.Contains(t, stderr, "--allow-unauthenticated-bind")
}
