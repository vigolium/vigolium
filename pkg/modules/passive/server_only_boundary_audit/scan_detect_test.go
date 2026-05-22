package server_only_boundary_audit

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// makeHTTPCtx builds a request/response pair with the given path, content type, and body.
func makeHTTPCtx(path, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_PrismaLeak drives a client bundle that imports a Prisma client,
// which is server-only code leaked into the browser.
func TestScanPerRequest_PrismaLeak(t *testing.T) {
	t.Parallel()
	m := New()
	body := `import {PrismaClient} from "@prisma/client"; const db = new PrismaClient();`
	ctx := makeHTTPCtx("/_next/static/chunks/main.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		assert.Equal(t, ModuleID, r.ModuleID)
		if r.Info.Name == "Server Code Leak: Database Client (Prisma)" {
			found = true
		}
	}
	assert.True(t, found, "expected Prisma database client leak finding")
}

// TestScanPerRequest_ConnectionString drives a bundle containing a credentialed
// database connection string, the highest-severity leak.
func TestScanPerRequest_ConnectionString(t *testing.T) {
	t.Parallel()
	m := New()
	body := `const url = "postgres://admin:secret@db.internal/app";`
	ctx := makeHTTPCtx("/_next/static/chunks/app.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Server Code Leak: Database Connection String" {
			found = true
		}
	}
	assert.True(t, found, "expected database connection string leak finding")
}

// TestScanPerRequest_CleanBundle verifies that a benign client bundle produces no
// findings.
func TestScanPerRequest_CleanBundle(t *testing.T) {
	t.Parallel()
	m := New()
	body := `import React from "react"; export default function App(){ return null; }`
	ctx := makeHTTPCtx("/_next/static/chunks/clean.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
