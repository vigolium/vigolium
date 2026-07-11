package grpc_surface_audit

import (
	"fmt"
	"math"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/grpcweb"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// grpcContentType is the request content type used for synthesized probes.
const grpcContentType = "application/grpc-web+proto"

// grpcStatusUnimplemented is UNIMPLEMENTED — a registered gRPC server returns it
// for methods (or whole services) that do not exist, so it marks a service ABSENT.
const grpcStatusUnimplemented = "12"

// grpcStatusOK is OK — a decoded gRPC-Web reply carrying this status succeeded.
const grpcStatusOK = "0"

// reflectionHealthPaths are the well-known gRPC services whose presence reveals
// an enumerable / debug surface. We probe existence only; parsing the protobuf
// descriptors that reflection returns is a documented follow-up (see scanner.go).
var reflectionHealthPaths = []struct {
	path string
	name string
}{
	{"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "server reflection"},
	{"/grpc.health.v1.Health/Check", "health"},
}

// ---------------------------------------------------------------------------
// Check A: reflection / health existence probe (Info)
// ---------------------------------------------------------------------------

// checkReflectionHealth POSTs a minimal framed request to the well-known
// reflection and health services and reports (Info) when one is PRESENT and the
// verdict is stable across two probes. A grpc-status 12 (UNIMPLEMENTED) or an
// HTTP 404 means ABSENT; any other decodable gRPC-Web reply means PRESENT.
func (m *Module) checkReflectionHealth(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	u *urlutil.URL,
) *output.ResultEvent {
	for _, svc := range reflectionHealthPaths {
		// Build the framed probe once, then execute it twice for the stability check
		// (both probes are byte-identical — there is no per-request nonce).
		raw, err := buildProbeRaw(ctx.Request().Raw(), svc.path, grpcweb.EncodeFrame(false, nil))
		if err != nil {
			continue
		}
		p1, ok1 := m.probeOnce(ctx, httpClient, raw)
		if !ok1 {
			continue
		}
		p2, ok2 := m.probeOnce(ctx, httpClient, raw)
		if !ok2 {
			continue
		}
		// Require a stable PRESENT verdict across both probes before reporting.
		if !p1.present || !p2.present {
			continue
		}

		endpoint := u.Scheme + "://" + u.Host + svc.path
		return &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             u.Host,
			URL:              endpoint,
			Matched:          endpoint,
			FuzzingParameter: svc.path,
			ExtractedResults: []string{
				fmt.Sprintf("gRPC %s service present at %s (grpc-status %s, stable across 2 probes)", svc.name, svc.path, p1.status),
			},
			Metadata: map[string]interface{}{
				"rpc_path":    svc.path,
				"service":     svc.name,
				"grpc_status": p1.status,
			},
			Info: output.Info{
				Name:        "gRPC Reflection/Health Service Exposed",
				Description: "A well-known gRPC service (reflection or health) answers requests on this endpoint, exposing an enumerable RPC/debug surface. Reflection lets a client download the full service/method catalog and message schemas.",
				Severity:    severity.Info,
				Confidence:  severity.Firm,
				Tags:        ModuleTags,
			},
		}
	}
	return nil
}

// probeResult is a single reflection/health existence verdict.
type probeResult struct {
	present bool
	status  string // grpc-status observed ("" when derived from HTTP 404)
}

// probeOnce executes one pre-built framed probe and classifies service presence.
func (m *Module) probeOnce(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	raw []byte,
) (probeResult, bool) {
	res, ok := m.executeRaw(ctx, httpClient, raw)
	if !ok {
		return probeResult{}, false
	}
	// HTTP 404 → the gateway does not route the service at all → ABSENT.
	if res.httpCode == 404 {
		return probeResult{present: false}, true
	}
	// A non-gRPC-Web reply (some other error page) is ambiguous — treat as ABSENT
	// to avoid a false positive.
	if !res.decoded {
		return probeResult{present: false}, true
	}
	// UNIMPLEMENTED → the server is gRPC but this service is not registered → ABSENT.
	if res.grpcStatus == grpcStatusUnimplemented {
		return probeResult{present: false, status: res.grpcStatus}, true
	}
	// Anything else (OK, INVALID_ARGUMENT, INTERNAL, ...) means the service IS
	// registered and answered → PRESENT.
	return probeResult{present: true, status: res.grpcStatus}, true
}

// ---------------------------------------------------------------------------
// Check B: missing-authorization replay (primary finding), multi-round
// ---------------------------------------------------------------------------

// baselineTolerance is the fractional data-length band within which a no-auth
// replay must match the authed baseline to count as "the same substantive data".
const baselineTolerance = 0.25

// stableTolerance is the tighter band the two no-auth rounds (and the two authed
// baseline fetches) must agree within, to reject nondeterministic/streaming noise.
const stableTolerance = 0.10

// checkMissingAuthz replays an idempotent read RPC with credentials stripped and
// reports High/Firm when the unauthenticated call still returns grpc-status 0
// with substantive, stable data matching the authed baseline.
func (m *Module) checkMissingAuthz(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	u *urlutil.URL,
) *output.ResultEvent {
	// Only touch RPC-shaped paths.
	if !grpcweb.IsRPCPath(u.Path) {
		return nil
	}
	method := rpcMethod(u.Path)
	// SAFETY: only replay idempotent-looking reads, and NEVER anything that looks
	// mutating — replaying Create/Delete/Transfer/... could change server state.
	if !isIdempotentRPC(method) || isMutatingRPC(method) {
		return nil
	}

	seedRaw := ctx.Request().Raw()

	// A "missing authorization" bypass is only meaningful when the original
	// request actually carried credentials; without an authed baseline there is
	// nothing to compare against.
	if !hasCredentials(seedRaw) {
		return nil
	}

	// Establish a STABLE authed baseline: replay the exact request verbatim twice
	// and require both to succeed with substantive, agreeing payloads.
	base1, ok := m.executeRaw(ctx, httpClient, seedRaw)
	if !ok || !base1.grpcSuccess() || !base1.substantive() {
		return nil
	}
	base2, ok := m.executeRaw(ctx, httpClient, seedRaw)
	if !ok || !base2.grpcSuccess() || !base2.substantive() {
		return nil
	}
	if !stablePayload(base1, base2) {
		return nil
	}

	// Build the credential-stripped request.
	noAuthRaw, err := httpmsg.RemoveHeader(seedRaw, "Authorization")
	if err != nil {
		return nil
	}
	noAuthRaw, err = httpmsg.RemoveHeader(noAuthRaw, "Cookie")
	if err != nil {
		return nil
	}

	// Round 1: unauthenticated replay must succeed with substantive data that is
	// similar in size/shape to the authed baseline.
	na1, ok := m.executeRaw(ctx, httpClient, noAuthRaw)
	if !ok || !na1.grpcSuccess() || !na1.substantive() {
		return nil // correctly protected: 401/403/permission-denied/undecodable
	}
	if !similarSize(base1.dataLen, na1.dataLen, baselineTolerance) {
		return nil
	}

	// Round 2 (multi-round confirmation): the same grpc-status 0 + stable payload
	// must reproduce, killing nondeterministic/streaming one-shot matches.
	na2, ok := m.executeRaw(ctx, httpClient, noAuthRaw)
	if !ok || !na2.grpcSuccess() || !na2.substantive() {
		return nil
	}
	if !stablePayload(na1, na2) {
		return nil
	}

	ev := modkit.NewEvidenceCollector()
	ev.Add("authed-baseline", base1.rawReq, base1.rawResp)
	ev.Add("no-auth round 1", na1.rawReq, na1.rawResp)
	ev.Add("no-auth round 2", na2.rawReq, na2.rawResp)

	// Optional, self-disabling corroboration: replay through any configured
	// lower-privilege identity and attach the result as extra evidence. No-op when
	// SetCompareClients was never called (the default; the runner does not wire it).
	if m.HasCompareClients() {
		clients, labels := m.compareIdentities()
		for i, c := range clients {
			if c == nil {
				continue
			}
			label := "compare-identity"
			if i < len(labels) && labels[i] != "" {
				label = "compare: " + labels[i]
			}
			if res, cok := m.executeRaw(ctx, c, noAuthRaw); cok {
				ev.Add(label, res.rawReq, res.rawResp)
			}
		}
	}

	return &output.ResultEvent{
		ModuleID:           ModuleID,
		Host:               u.Host,
		URL:                u.String(),
		Matched:            u.String(),
		Request:            na1.rawReq,
		Response:           na1.rawResp,
		AdditionalEvidence: ev.Entries(),
		FuzzingParameter:   u.Path,
		ExtractedResults: []string{
			fmt.Sprintf("RPC %s returns grpc-status 0 with %d bytes after removing Authorization and Cookie", u.Path, na1.dataLen),
			fmt.Sprintf("Authed baseline: %d bytes; no-auth rounds: %d / %d bytes", base1.dataLen, na1.dataLen, na2.dataLen),
		},
		Metadata: map[string]interface{}{
			"rpc_path":      u.Path,
			"grpc_status":   na1.grpcStatus,
			"rounds":        2,
			"decoded_bytes": na1.dataLen,
		},
		Info: output.Info{
			Name:        "gRPC-Web Missing Authorization",
			Description: "An idempotent gRPC-Web read method returns a successful response (grpc-status 0) with substantive data after the Authorization and Cookie headers are removed, and the result reproduces across multiple rounds. The method enforces no authorization.",
			Severity:    severity.High,
			Confidence:  severity.Firm,
			Tags:        ModuleTags,
		},
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildProbeRaw mints a POST gRPC-Web request off seedRaw at path with body, so
// the probe inherits the seed's host/cookies/auth while retargeting the RPC.
func buildProbeRaw(seedRaw []byte, path string, body []byte) ([]byte, error) {
	raw, err := httpmsg.SetMethod(seedRaw, "POST")
	if err != nil {
		return nil, err
	}
	if raw, err = httpmsg.SetPath(raw, path); err != nil {
		return nil, err
	}
	if raw, err = httpmsg.SetBodyString(raw, string(body)); err != nil {
		return nil, err
	}
	if raw, err = httpmsg.AddOrReplaceHeader(raw, "Content-Type", grpcContentType); err != nil {
		return nil, err
	}
	return raw, nil
}

// idempotentPrefixes are the method-name prefixes considered safe to replay.
var idempotentPrefixes = []string{
	"get", "list", "read", "query", "search", "fetch", "describe", "lookup", "watch", "check",
}

// mutatingTokens are substrings that mark a method as state-changing; a method
// containing any of these is NEVER replayed, even if it also starts with a read
// prefix (e.g. "GetOrCreate").
var mutatingTokens = []string{
	"create", "update", "delete", "remove", "set", "put", "write",
	"pay", "charge", "transfer", "admin", "exec", "run", "send",
}

// rpcMethod returns the method segment of a gRPC path "/package.Service/Method".
func rpcMethod(path string) string {
	idx := strings.LastIndexByte(path, '/')
	if idx < 0 || idx+1 >= len(path) {
		return ""
	}
	return path[idx+1:]
}

// isIdempotentRPC reports whether method starts with a read/query verb.
func isIdempotentRPC(method string) bool {
	ml := strings.ToLower(method)
	for _, p := range idempotentPrefixes {
		if strings.HasPrefix(ml, p) {
			return true
		}
	}
	return false
}

// isMutatingRPC reports whether method contains a state-changing token.
func isMutatingRPC(method string) bool {
	ml := strings.ToLower(method)
	for _, tok := range mutatingTokens {
		if strings.Contains(ml, tok) {
			return true
		}
	}
	return false
}

// similarSize reports whether two message lengths are within tol of each other.
func similarSize(a, b int, tol float64) bool {
	if a == 0 && b == 0 {
		return true
	}
	if a == 0 || b == 0 {
		return false
	}
	larger := a
	if b > larger {
		larger = b
	}
	return math.Abs(float64(a-b))/float64(larger) <= tol
}

// stablePayload reports whether two replay results agree on grpc-status and are
// within the tighter stability band on message length.
func stablePayload(a, b replayResult) bool {
	return a.grpcStatus == b.grpcStatus && similarSize(a.dataLen, b.dataLen, stableTolerance)
}
