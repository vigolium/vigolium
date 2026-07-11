// Package grpc_surface_audit is an active security audit for gRPC-Web endpoints
// spoken over HTTP/1.1. It reuses the standard vigolium HTTP requester plus the
// pure-Go frame codec in pkg/modules/infra/grpcweb — it deliberately does NOT
// link google.golang.org/grpc or google.golang.org/protobuf, and it does NOT
// speak native HTTP/2 gRPC.
//
// Scope today: two checks over gRPC-Web framing (see checks.go):
//
//	A. Reflection / health service existence probe (Info).
//	B. Missing-authorization replay on idempotent read RPCs (High, the primary
//	   finding), multi-round confirmed.
//
// Explicit, DOCUMENTED follow-ups (NOT implemented here — each needs the two
// forbidden dependencies and so is out of scope for the pure-Go codec):
//
//	C. Descriptor-guided input testing: pull the protobuf FileDescriptorSet from
//	   server reflection, decode it with google.golang.org/protobuf, and fuzz
//	   typed fields (oversize, boundary, enum, oneof) per method. Requires
//	   protobuf descriptor parsing.
//	D. Resource-limit / DoS checks: oversized length-prefixed messages, deeply
//	   nested messages, and streaming-flood behavior — needs a real protobuf
//	   encoder to build well-formed adversarial messages.
//	+ Native HTTP/2 gRPC (application/grpc): the same authz / reflection logic
//	  over an h2 transport with real HTTP trailers, which requires
//	  google.golang.org/grpc. This module is gRPC-Web / HTTP-1.1 ONLY.
package grpc_surface_audit

import (
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/grpcweb"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// Module implements the gRPC-Web Surface Audit active scanner.
type Module struct {
	modkit.BaseActiveModule

	// reflectionSeen dedups the reflection/health existence probe (Check A) to
	// once per host for the lifetime of this (singleton) module instance.
	reflectionSeen sync.Map // host(string) -> struct{}

	// Optional, self-disabling lower-privilege comparison identities. If the
	// parent wires them via SetCompareClients, Check B additionally replays the
	// authorization-stripped request through each and records the result as
	// corroborating evidence. When unset (the default), Check B relies on the
	// no-auth replay alone. The runner does NOT wire these today.
	compareMu      sync.RWMutex
	compareClients []*http.Requester
	compareLabels  []string
}

// New creates a new gRPC-Web Surface Audit module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
	}
	m.ModuleTags = ModuleTags
	return m
}

// Priority runs the audit after cheaper/lighter modules so tech tagging has
// settled. Lower is earlier; 200 is below the default of 100.
func (m *Module) Priority() int { return 200 }

// RequiredTechs gates the module to hosts a fingerprint/passive module has
// tagged "grpc-web". The executor fails open on unknown hosts, so ScanPerRequest
// re-checks the tag explicitly (a hard fail-closed gate) before doing any work.
func (m *Module) RequiredTechs() []string { return []string{"grpc-web"} }

// SetCompareClients installs optional lower-privilege comparison identities used
// by Check B (see the Module doc). labels[i] names clients[i] for evidence. Pass
// nil to clear. Safe for concurrent use.
func (m *Module) SetCompareClients(clients []*http.Requester, labels []string) {
	m.compareMu.Lock()
	defer m.compareMu.Unlock()
	m.compareClients = clients
	m.compareLabels = labels
}

// HasCompareClients reports whether any comparison identity is configured.
func (m *Module) HasCompareClients() bool {
	m.compareMu.RLock()
	defer m.compareMu.RUnlock()
	return len(m.compareClients) > 0
}

// compareIdentities returns a snapshot of the configured comparison clients and
// their labels for Check B to iterate without holding the lock.
func (m *Module) compareIdentities() ([]*http.Requester, []string) {
	m.compareMu.RLock()
	defer m.compareMu.RUnlock()
	return m.compareClients, m.compareLabels
}

// ScanPerRequest audits a single gRPC-Web request for missing authorization and
// exposed reflection/health services.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	u, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := u.Host

	// HARD fail-closed tech gate: only ever run against a host explicitly tagged
	// gRPC-Web. Unlike the executor's fail-open RequiredTechs pre-filter, this
	// refuses to run on unknown hosts so the module never fires on non-gRPC
	// traffic that happens to reach it.
	if !scanCtx.HasTech(host, "grpc-web") {
		return nil, nil
	}

	// Additionally require THIS request/response to actually look gRPC-Web (a
	// gRPC-Web content type on either side). The tech tag is per-host; this keeps
	// us from replaying an ordinary REST request on a host that also serves gRPC.
	if !looksGRPCWeb(ctx) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Check A: reflection/health existence probe, once per host.
	if _, seen := m.reflectionSeen.LoadOrStore(host, struct{}{}); !seen {
		if r := m.checkReflectionHealth(ctx, httpClient, u); r != nil {
			results = append(results, r)
		}
	}

	// Check B: missing-authorization replay (the primary finding).
	if r := m.checkMissingAuthz(ctx, httpClient, u); r != nil {
		results = append(results, r)
	}

	return results, nil
}

// looksGRPCWeb reports whether either side of ctx carries a gRPC-Web content type.
func looksGRPCWeb(ctx *httpmsg.HttpRequestResponse) bool {
	if req := ctx.Request(); req != nil {
		if ok, _ := grpcweb.IsGRPCWebContentType(req.Header("Content-Type")); ok {
			return true
		}
	}
	if resp := ctx.Response(); resp != nil {
		if ok, _ := grpcweb.IsGRPCWebContentType(resp.Header("Content-Type")); ok {
			return true
		}
	}
	return false
}

// replayResult captures the decoded outcome of a single gRPC-Web request replay.
type replayResult struct {
	httpCode   int    // HTTP status code of the transport response
	grpcStatus string // decoded grpc-status ("" if none)
	dataLen    int    // total bytes across all non-trailer (message) frames
	decoded    bool   // response decoded as a valid gRPC-Web body
	rawReq     string // raw request sent (for evidence)
	rawResp    string // full raw response (for evidence)
}

// grpcSuccess reports a decoded gRPC-Web response whose call succeeded
// (grpc-status 0). A non-decodable response, an HTTP 401/403, a WAF/edge block,
// or any non-zero grpc-status all return false — those are correctly protected.
func (r replayResult) grpcSuccess() bool {
	return r.decoded && r.grpcStatus == grpcStatusOK
}

// substantive reports that the successful response carried a non-empty message
// frame (actual data), not just an empty grpc-status 0 acknowledgement.
func (r replayResult) substantive() bool {
	return r.dataLen > 0
}

// executeRaw sends a fully-formed raw request through client and decodes the
// response as gRPC-Web. NoClustering is set so repeated identical replays hit the
// server every time (essential for the multi-round stability checks). ok is false
// only on a transport error / missing response.
func (m *Module) executeRaw(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	raw []byte,
) (replayResult, bool) {
	// raw comes from httpmsg builders (well-formed), so wrap directly rather than
	// re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil || resp == nil {
		return replayResult{}, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return replayResult{}, false
	}

	rr := replayResult{
		httpCode: resp.Response().StatusCode,
		rawReq:   string(raw),
		rawResp:  resp.FullResponseString(),
	}

	ct := resp.Response().Header.Get("Content-Type")
	// resp.Body() stays valid until the deferred resp.Close(), and grpcweb.DecodeBody
	// copies out each retained frame's bytes — so no defensive body copy is needed.
	body := resp.Body().Bytes()
	statusHeader := resp.Response().Header.Get("grpc-status")

	// Only treat the response as gRPC-Web when the content type says so; this
	// keeps a 401 HTML page or a WAF block from being misread as a gRPC reply.
	if ok, _ := grpcweb.IsGRPCWebContentType(ct); !ok {
		return rr, true
	}

	frames, _ := grpcweb.DecodeBody(ct, body)
	for _, f := range frames {
		if !f.Trailer {
			rr.dataLen += len(f.Data)
		}
	}
	if code, ok := grpcweb.GRPCStatus(frames); ok {
		rr.grpcStatus = code
		rr.decoded = true
	} else if statusHeader != "" {
		rr.grpcStatus = statusHeader
		rr.decoded = true
	} else if len(frames) > 0 {
		// Framed data but no trailer status yet (streaming/partial) — still a
		// decodable gRPC-Web body.
		rr.decoded = true
	}
	return rr, true
}

// hasCredentials reports whether the seed request presented an Authorization
// header or a Cookie — the credentials a missing-authz test needs to strip.
func hasCredentials(raw []byte) bool {
	authVal, _ := httpmsg.GetHeaderValue(raw, "Authorization")
	cookieVal, _ := httpmsg.GetHeaderValue(raw, "Cookie")
	return strings.TrimSpace(authVal) != "" || strings.TrimSpace(cookieVal) != ""
}
