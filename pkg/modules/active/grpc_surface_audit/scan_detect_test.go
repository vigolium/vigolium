package grpc_surface_audit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/grpcweb"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	nameMissingAuthz = "gRPC-Web Missing Authorization"
	nameReflection   = "gRPC Reflection/Health Service Exposed"
	grpcCT           = "application/grpc-web+proto"
)

// writeGRPCWeb writes a gRPC-Web framed response: an optional data frame followed
// by a trailer frame carrying grpc-status.
func writeGRPCWeb(w http.ResponseWriter, code int, payload []byte, grpcStatus string) {
	w.Header().Set("Content-Type", grpcCT)
	w.WriteHeader(code)
	var buf []byte
	if len(payload) > 0 {
		buf = append(buf, grpcweb.EncodeFrame(false, payload)...)
	}
	buf = append(buf, grpcweb.EncodeFrame(true, []byte("grpc-status:"+grpcStatus+"\r\n"))...)
	_, _ = w.Write(buf)
}

// grpcSeed builds a POST gRPC-Web seed request routed at the test server, with an
// optional Authorization header and a framed body.
func grpcSeed(t testing.TB, rawURL, path, auth string, body []byte) *httpmsg.HttpRequestResponse {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)

	port := 80
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		require.NoError(t, err)
	} else if u.Scheme == "https" {
		port = 443
	}
	svc, err := httpmsg.NewService(u.Hostname(), port, u.Scheme)
	require.NoError(t, err)

	var b strings.Builder
	fmt.Fprintf(&b, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\n", path, u.Host, grpcCT)
	if auth != "" {
		fmt.Fprintf(&b, "Authorization: %s\r\n", auth)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	b.Write(body)

	req := httpmsg.NewHttpRequestWithService(svc, []byte(b.String()))
	return httpmsg.NewHttpRequestResponse(req, nil)
}

// markedCtx builds a ScanContext with the seed's host tagged gRPC-Web.
func markedCtx(t testing.TB, seed *httpmsg.HttpRequestResponse) *modkit.ScanContext {
	t.Helper()
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	u, err := seed.URL()
	require.NoError(t, err)
	sc.MarkTech(u.Host, "grpc-web")
	return sc
}

func findByName(res []*output.ResultEvent, name string) *output.ResultEvent {
	for _, r := range res {
		if r.Info.Name == name {
			return r
		}
	}
	return nil
}

func framedReqBody() []byte { return grpcweb.EncodeFrame(false, []byte("request-message")) }

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.High, m.Severity())
	assert.Equal(t, []string{"grpc-web"}, m.RequiredTechs())
	assert.Equal(t, 200, m.Priority())
	assert.False(t, m.HasCompareClients())
}

// Case 1: VULNERABLE — the no-auth replay returns grpc-status 0 with data across
// both rounds, so a High/Firm missing-authorization finding is produced.
func TestScanPerRequest_MissingAuthz_Vulnerable(t *testing.T) {
	t.Parallel()
	payload := []byte("secret-user-record-abcdef0123456789")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pkg.Svc/GetThing" {
			// Returns data regardless of credentials → missing authorization.
			writeGRPCWeb(w, http.StatusOK, payload, "0")
			return
		}
		w.WriteHeader(http.StatusNotFound) // reflection/health absent
	}))
	defer srv.Close()

	seed := grpcSeed(t, srv.URL, "/pkg.Svc/GetThing", "Bearer valid-token", framedReqBody())
	sc := markedCtx(t, seed)

	res, err := New().ScanPerRequest(seed, modtest.Requester(t), sc)
	require.NoError(t, err)

	f := findByName(res, nameMissingAuthz)
	require.NotNil(t, f, "expected a missing-authorization finding")
	assert.Equal(t, severity.High, f.Info.Severity)
	assert.Equal(t, severity.Firm, f.Info.Confidence)
	assert.Equal(t, "/pkg.Svc/GetThing", f.FuzzingParameter)
	assert.Equal(t, "/pkg.Svc/GetThing", f.Metadata["rpc_path"])
	assert.Equal(t, "0", f.Metadata["grpc_status"])
	assert.NotEmpty(t, f.AdditionalEvidence, "baseline + no-auth rounds must be recorded")

	assert.Nil(t, findByName(res, nameReflection), "no reflection service is exposed here")
}

// Case 2a: PROTECTED via HTTP 401 — the no-auth replay is rejected, so no finding.
func TestScanPerRequest_MissingAuthz_Protected401(t *testing.T) {
	t.Parallel()
	payload := []byte("secret-user-record-abcdef0123456789")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pkg.Svc/GetThing" {
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("unauthorized"))
				return
			}
			writeGRPCWeb(w, http.StatusOK, payload, "0")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	seed := grpcSeed(t, srv.URL, "/pkg.Svc/GetThing", "Bearer valid-token", framedReqBody())
	sc := markedCtx(t, seed)

	res, err := New().ScanPerRequest(seed, modtest.Requester(t), sc)
	require.NoError(t, err)
	assert.Nil(t, findByName(res, nameMissingAuthz), "a 401 on the no-auth replay is correctly protected")
}

// Case 2b: PROTECTED via grpc-status 7 PERMISSION_DENIED — application-level
// denial (decodes as gRPC-Web but not status 0) must not be flagged.
func TestScanPerRequest_MissingAuthz_ProtectedPermissionDenied(t *testing.T) {
	t.Parallel()
	payload := []byte("secret-user-record-abcdef0123456789")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pkg.Svc/GetThing" {
			if r.Header.Get("Authorization") == "" {
				writeGRPCWeb(w, http.StatusOK, nil, "7") // PERMISSION_DENIED
				return
			}
			writeGRPCWeb(w, http.StatusOK, payload, "0")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	seed := grpcSeed(t, srv.URL, "/pkg.Svc/GetThing", "Bearer valid-token", framedReqBody())
	sc := markedCtx(t, seed)

	res, err := New().ScanPerRequest(seed, modtest.Requester(t), sc)
	require.NoError(t, err)
	assert.Nil(t, findByName(res, nameMissingAuthz), "grpc-status 7 PERMISSION_DENIED is correctly protected")
}

// Case 3: non-idempotent method — /pkg.Svc/DeleteThing must NEVER be replayed,
// even when the server would answer the no-auth call with data.
func TestScanPerRequest_NonIdempotentNeverProbed(t *testing.T) {
	t.Parallel()
	payload := []byte("would-look-vulnerable-if-probed-0123456789")
	var deleteCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pkg.Svc/DeleteThing" {
			deleteCalls++
			writeGRPCWeb(w, http.StatusOK, payload, "0")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	seed := grpcSeed(t, srv.URL, "/pkg.Svc/DeleteThing", "Bearer valid-token", framedReqBody())
	sc := markedCtx(t, seed)

	res, err := New().ScanPerRequest(seed, modtest.Requester(t), sc)
	require.NoError(t, err)
	assert.Nil(t, findByName(res, nameMissingAuthz), "a mutating method must not be replayed")
	assert.Zero(t, deleteCalls, "the mutating RPC must never be sent")
}

// Case 4: tech not marked — the hard fail-closed gate returns nothing and sends
// no traffic at all.
func TestScanPerRequest_TechGateClosed(t *testing.T) {
	t.Parallel()
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeGRPCWeb(w, http.StatusOK, []byte("data-0123456789"), "0")
	}))
	defer srv.Close()

	seed := grpcSeed(t, srv.URL, "/pkg.Svc/GetThing", "Bearer valid-token", framedReqBody())
	// TechStack present but grpc-web NOT marked → gate closed.
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}

	res, err := New().ScanPerRequest(seed, modtest.Requester(t), sc)
	require.NoError(t, err)
	assert.Empty(t, res, "no findings without the grpc-web tech tag")
	assert.Zero(t, calls, "no traffic must be sent when the tech gate is closed")

	// Nil TechStack must also fail closed.
	res, err = New().ScanPerRequest(seed, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

// Case 5a: reflection PRESENT (grpc-status != 12, stable) → Info finding.
func TestScanPerRequest_ReflectionPresent(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
			"/grpc.health.v1.Health/Check":
			// Present: server answers with a non-12 status (INVALID_ARGUMENT).
			writeGRPCWeb(w, http.StatusOK, nil, "3")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// No Authorization → Check B is skipped, isolating Check A.
	seed := grpcSeed(t, srv.URL, "/pkg.Svc/GetData", "", framedReqBody())
	sc := markedCtx(t, seed)

	res, err := New().ScanPerRequest(seed, modtest.Requester(t), sc)
	require.NoError(t, err)

	f := findByName(res, nameReflection)
	require.NotNil(t, f, "an exposed reflection/health service must be reported")
	assert.Equal(t, severity.Info, f.Info.Severity)
	assert.Nil(t, findByName(res, nameMissingAuthz))
}

// Case 5b: reflection ABSENT (grpc-status 12 / HTTP 404) → no Info finding.
func TestScanPerRequest_ReflectionAbsent(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo":
			writeGRPCWeb(w, http.StatusOK, nil, "12") // UNIMPLEMENTED
		default:
			w.WriteHeader(http.StatusNotFound) // health → 404
		}
	}))
	defer srv.Close()

	seed := grpcSeed(t, srv.URL, "/pkg.Svc/GetData", "", framedReqBody())
	sc := markedCtx(t, seed)

	res, err := New().ScanPerRequest(seed, modtest.Requester(t), sc)
	require.NoError(t, err)
	assert.Nil(t, findByName(res, nameReflection), "UNIMPLEMENTED/404 reflection must not be reported")
}
