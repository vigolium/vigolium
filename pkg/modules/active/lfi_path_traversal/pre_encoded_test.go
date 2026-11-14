package lfi_path_traversal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// A target that only falls for the double-encoded traversal: its raw query must
// carry "%252e%252e%252f" as written. Through BuildRequest the payload arrived
// as "%25252e…" and the module could never fire.
func TestScanPerInsertionPoint_DoubleEncodedPayloadArrivesAsWritten(t *testing.T) {
	var sawDouble bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "file=%252e%252e%252f") {
			sawDouble = true
			_, _ = io.WriteString(w, passwdBody)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/?file=welcome"), "text/html", cleanBaseline)
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.True(t, sawDouble, "the %252e payload never reached the server as written")
	require.NotEmpty(t, res)
}
