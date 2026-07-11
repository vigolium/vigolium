package server_only_boundary_audit

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
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

// TestScanPerRequest_CorroboratedLeak drives a client bundle that leaks TWO
// distinct server-only signals (Prisma client + Node fs require). With
// corroboration present, both are reported.
func TestScanPerRequest_CorroboratedLeak(t *testing.T) {
	t.Parallel()
	m := New()
	body := `import {PrismaClient} from "@prisma/client"; const db = new PrismaClient();` +
		` const fs = require("fs"); fs.readFileSync("/etc/secret");`
	ctx := makeHTTPCtx("/_next/static/chunks/main.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		assert.Equal(t, ModuleID, r.ModuleID)
		if r.Info.Name == "Server-Boundary Candidate: Database Client (Prisma)" {
			found = true
			assert.Equal(t, output.RecordKindCandidate, r.RecordKind)
			assert.False(t, r.IsFinding())
		}
	}
	assert.True(t, found, "expected Prisma leak when corroborated by a second server-only signal")
}

// TestScanPerRequest_LoneWeakMatchDropped ensures a single weak server-only
// pattern (a lone Prisma reference, as commonly seen as an incidental string in a
// minified vendor bundle) is NOT reported without corroboration.
func TestScanPerRequest_LoneWeakMatchDropped(t *testing.T) {
	t.Parallel()
	m := New()
	body := `import {PrismaClient} from "@prisma/client"; const db = new PrismaClient();`
	ctx := makeHTTPCtx("/_next/static/chunks/main.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a lone weak server-only pattern must require corroboration")
}

// TestScanPerRequest_ConnectionString drives a bundle containing a credentialed
// database connection string, the highest-severity leak.
func TestScanPerRequest_ConnectionString(t *testing.T) {
	t.Parallel()
	m := New()
	body := `const url = "postgres://admin:8Pz7vR3mQ2xL@db.internal/app";`
	ctx := makeHTTPCtx("/_next/static/chunks/app.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Server-Boundary Candidate: Database Connection String" {
			found = true
			assert.Equal(t, output.RecordKindCandidate, r.RecordKind)
		}
	}
	assert.True(t, found, "expected database connection string leak finding")
}

func TestConnectionStringPlaceholderDropped(t *testing.T) {
	t.Parallel()
	ctx := makeHTTPCtx("/_next/static/chunks/app.js", "application/javascript", `const url="postgres://user:changeme123@example.internal/app";`)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
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
