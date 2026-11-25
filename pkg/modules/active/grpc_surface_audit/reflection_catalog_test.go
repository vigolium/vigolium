package grpc_surface_audit

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/infra/grpcweb"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func pbField(b []byte, num int, v []byte) []byte {
	b = binary.AppendUvarint(b, uint64(num)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func pbVarint(b []byte, num int, v uint64) []byte {
	b = binary.AppendUvarint(b, uint64(num)<<3)
	return binary.AppendUvarint(b, v)
}

// reflectionServer answers grpc.reflection.v1 ServerReflectionInfo over
// gRPC-Web: list_services names two services, file_containing_symbol returns
// the descriptor for acme.v1.Users only (the other gets NOT_FOUND), and an
// empty request (the existence probe) gets INVALID_ARGUMENT.
func reflectionServer(t *testing.T) *httptest.Server {
	t.Helper()
	method := func(name, in, out string, ss bool) []byte {
		m := pbField(nil, 1, []byte(name))
		m = pbField(m, 2, []byte(in))
		m = pbField(m, 3, []byte(out))
		if ss {
			m = pbVarint(m, 6, 1)
		}
		return m
	}
	svc := pbField(nil, 1, []byte("Users"))
	svc = pbField(svc, 2, method("GetUser", ".acme.v1.GetUserRequest", ".acme.v1.User", false))
	svc = pbField(svc, 2, method("WatchUsers", ".acme.v1.WatchRequest", ".acme.v1.User", true))
	fd := pbField(nil, 1, []byte("acme/v1/users.proto"))
	fd = pbField(fd, 2, []byte("acme.v1"))
	fd = pbField(fd, 6, svc)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != grpcweb.ReflectionPaths[0] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		frames, _ := grpcweb.DecodeFrames(body)
		var req []byte
		if len(frames) > 0 {
			req = frames[0].Data
		}
		switch {
		case bytes.Equal(req, grpcweb.EncodeListServicesRequest()):
			list := pbField(nil, 1, pbField(nil, 1, []byte("acme.v1.Users")))
			list = pbField(list, 1, pbField(nil, 1, []byte("acme.v1.Billing")))
			writeGRPCWeb(w, http.StatusOK, pbField(nil, 6, list), "0")
		case bytes.Equal(req, grpcweb.EncodeFileContainingSymbolRequest("acme.v1.Users")):
			writeGRPCWeb(w, http.StatusOK, pbField(nil, 4, pbField(nil, 1, fd)), "0")
		case len(req) > 0:
			e := pbVarint(nil, 1, 5)
			e = pbField(e, 2, []byte("not found"))
			writeGRPCWeb(w, http.StatusOK, pbField(nil, 7, e), "0")
		default:
			writeGRPCWeb(w, http.StatusOK, nil, "3")
		}
	}))
}

// A present reflection service is catalogued: every listed service, the
// methods of each descriptor returned, with paths, types and streaming.
func TestScanPerRequest_ReflectionCatalog(t *testing.T) {
	t.Parallel()
	srv := reflectionServer(t)
	defer srv.Close()

	seed := grpcSeed(t, srv.URL, "/pkg.Svc/GetData", "", framedReqBody())
	res, err := New().ScanPerRequest(seed, modtest.Requester(t), markedCtx(t, seed))
	require.NoError(t, err)
	f := findByName(res, nameReflection)
	require.NotNil(t, f)

	catalog, ok := f.Metadata["services"].([]grpcweb.ReflectionService)
	require.True(t, ok, "metadata.services carries the catalog")
	require.Len(t, catalog, 2)
	assert.Equal(t, "acme.v1.Billing", catalog[0].Name)
	assert.Empty(t, catalog[0].Methods, "a service whose descriptor lookup failed is still listed")
	users := catalog[1]
	require.Len(t, users.Methods, 2)
	assert.Equal(t, "/acme.v1.Users/GetUser", users.Methods[0].Path)
	assert.Equal(t, "acme.v1.GetUserRequest", users.Methods[0].InputType)
	assert.True(t, users.Methods[1].ServerStreaming)
	assert.Equal(t, 2, f.Metadata["method_count"])
	assert.Contains(t, f.ExtractedResults, "rpc /acme.v1.Users/WatchUsers(acme.v1.WatchRequest) returns (acme.v1.User) [server-streaming]")
	assert.Equal(t, grpcweb.ReflectionPaths[0], f.Metadata["rpc_path"])
}
