package cli

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// replay -i sends a supplied request once; --baseline opts into the
// baseline send and diff.
func TestReplayInputSendsOnce(t *testing.T) {
	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	e := newB5Env(t)
	curl := "curl -X POST " + srv.URL + "/echo -d 'u=admin'"

	code, stdout, stderr := e.run(t, nil, "replay", "-i", curl, "-j")
	require.Equal(t, 0, code, stderr)
	require.EqualValues(t, 1, posts.Load(), stdout)

	posts.Store(0)
	code, _, stderr = e.run(t, nil, "replay", "-i", curl)
	require.Equal(t, 0, code, stderr)
	require.EqualValues(t, 1, posts.Load())

	posts.Store(0)
	code, stdout, stderr = e.run(t, nil, "replay", "-i", curl, "--baseline", "-j")
	require.Equal(t, 0, code, stderr)
	require.EqualValues(t, 2, posts.Load())
	require.Contains(t, stdout, `"diff":{`)
}
