package api_rate_limit_bypass

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

const rateLimitRequestCount = 10

var bypassHeaderNames = []string{
	"X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
	"X-Client-IP", "True-Client-IP", "X-Custom-IP-Authorization",
}

// RFC 5737 TEST-NET-3 addresses are non-routable documentation identities. They
// avoid conflating a loopback/private-address allowlist with rate-limit bypass.
const (
	spoofIdentityA = "203.0.113.101"
	spoofIdentityB = "203.0.113.102"
)

type responseObservation struct {
	status       int
	body         string
	fullResponse string // full raw response (status line + headers + body)
	ok           bool
}

type bypassProof struct {
	header         string
	identityA      string
	identityB      string
	bucketRotation bool
	statusA        int
	statusB        int
	// responseB is the full raw response of the successful identity-B request —
	// the finding's proof (its Request is the identity-B bypass request).
	responseB string
}

// Module implements the API Rate Limit Bypass active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeHost, modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("api_rate_limit_bypass"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil &&
		strings.EqualFold(ctx.Request().Method(), "GET") &&
		ctx.Response().StatusCode() >= 200 && ctx.Response().StatusCode() < 300 &&
		len(strings.TrimSpace(ctx.Response().BodyToString())) > 0
}

// ScanPerHost first establishes a live limiter, then sandwiches two distinct
// public test-net identities between repeated plain 429 controls. Response bodies
// must match the captured successful baseline. If one spoofed identity can itself
// be exhausted and a second identity immediately resets the bucket, the result is
// promoted from a candidate to a confirmed finding.
func (m *Module) ScanPerHost(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !m.CanProcess(ctx) || ctx.Service() == nil {
		return nil, nil
	}
	host := ctx.Service().Host()
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	if !m.triggerRateLimit(ctx, httpClient) || !m.plainConsistentlyLimited(ctx, httpClient) {
		return nil, nil
	}

	baseline := modkit.NewResponseSignature(ctx.Response().StatusCode(), ctx.Response().BodyToString(), "")
	for _, header := range bypassHeaderNames {
		proof, ok := m.proveHeaderDifferential(ctx, httpClient, baseline, header)
		if !ok {
			continue
		}

		kind := output.RecordKindCandidate
		grade := output.EvidenceGradeDifferential
		name := fmt.Sprintf("Rate Limit Identity Candidate via %s", header)
		description := fmt.Sprintf("Plain requests remained rate-limited while two distinct RFC 5737 values in %s each reproduced the successful baseline. This proves a header-dependent differential, but not yet that rotating values provides unbounded requests.", header)
		if proof.bucketRotation {
			kind = output.RecordKindFinding
			grade = output.EvidenceGradeBypass
			name = fmt.Sprintf("Rate Limit Bucket Rotation via %s", header)
			description = fmt.Sprintf("The scanner exhausted the rate-limit bucket for %s=%s, then immediately reproduced the successful baseline with %s while both the exhausted identity and plain requests remained 429. This confirms client-controlled bucket rotation.", header, proof.identityA, proof.identityB)
		}

		modifiedRaw, _ := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), header, proof.identityB)
		return []*output.ResultEvent{{
			ModuleID:      ModuleID,
			RecordKind:    kind,
			EvidenceGrade: grade,
			Host:          host,
			URL:           ctx.Target(),
			Matched:       ctx.Target(),
			Request:       string(modifiedRaw),
			Response:      proof.responseB,
			ExtractedResults: []string{
				fmt.Sprintf("header=%s identity_a=%s identity_b=%s", header, proof.identityA, proof.identityB),
				fmt.Sprintf("identity_a_status=%d identity_b_status=%d plain_status=429", proof.statusA, proof.statusB),
				fmt.Sprintf("per_identity_bucket_rotation=%t", proof.bucketRotation),
			},
			Info: output.Info{Name: name, Description: description, Severity: ModuleSeverity, Confidence: ModuleConfidence, Tags: ModuleTags},
			Metadata: map[string]any{
				"header":                 header,
				"identity_a":             proof.identityA,
				"identity_b":             proof.identityB,
				"bucket_rotation_proven": proof.bucketRotation,
				"safe_method":            "GET",
			},
		}}, nil
	}
	return nil, nil
}

func (m *Module) triggerRateLimit(ctx *httpmsg.HttpRequestResponse, client *http.Requester) bool {
	for range rateLimitRequestCount {
		observation := m.send(ctx, client, "", "")
		if !observation.ok {
			continue
		}
		if observation.status == 429 {
			return true
		}
	}
	return false
}

func (m *Module) proveHeaderDifferential(ctx *httpmsg.HttpRequestResponse, client *http.Requester, baseline modkit.ResponseSignature, header string) (bypassProof, bool) {
	proof := bypassProof{header: header, identityA: spoofIdentityA, identityB: spoofIdentityB}
	if !m.plainConsistentlyLimited(ctx, client) {
		return proof, false
	}

	aFirst := m.send(ctx, client, header, spoofIdentityA)
	aReplay := m.send(ctx, client, header, spoofIdentityA)
	if !matchesSuccessfulBaseline(aFirst, baseline) || !matchesSuccessfulBaseline(aReplay, baseline) {
		return proof, false
	}
	proof.statusA = aFirst.status
	if !m.plainConsistentlyLimited(ctx, client) {
		return proof, false
	}

	bFirst := m.sendProof(ctx, client, header, spoofIdentityB)
	if !matchesSuccessfulBaseline(bFirst, baseline) || !m.plainConsistentlyLimited(ctx, client) {
		return proof, false
	}
	proof.statusB = bFirst.status
	proof.responseB = bFirst.fullResponse

	// Strong confirmation: make identity A reach its own 429 bucket, then show B
	// still succeeds while A and the original/plain identity remain throttled.
	aLimited := false
	for range rateLimitRequestCount {
		if observation := m.send(ctx, client, header, spoofIdentityA); observation.ok && observation.status == 429 {
			aLimited = true
			break
		}
	}
	if !aLimited {
		return proof, true
	}
	if !m.plainConsistentlyLimited(ctx, client) {
		return proof, true
	}
	bAfterA := m.sendProof(ctx, client, header, spoofIdentityB)
	aAfter := m.send(ctx, client, header, spoofIdentityA)
	if matchesSuccessfulBaseline(bAfterA, baseline) && aAfter.ok && aAfter.status == 429 && m.plainConsistentlyLimited(ctx, client) {
		proof.bucketRotation = true
		proof.statusB = bAfterA.status
		proof.responseB = bAfterA.fullResponse
	}
	return proof, true
}

func matchesSuccessfulBaseline(observation responseObservation, baseline modkit.ResponseSignature) bool {
	if !observation.ok || observation.status < 200 || observation.status >= 300 {
		return false
	}
	signature := modkit.NewResponseSignature(observation.status, observation.body, "")
	return modkit.RatioSimilar(baseline, signature)
}

// plainConsistentlyLimited requires two of three fresh samples to remain 429.
// A single transient 429 or a reset window cannot satisfy the differential.
func (m *Module) plainConsistentlyLimited(ctx *httpmsg.HttpRequestResponse, client *http.Requester) bool {
	limited := 0
	for range 3 {
		if observation := m.send(ctx, client, "", ""); observation.ok && observation.status == 429 {
			limited++
		}
	}
	return limited >= 2
}

// send issues one probe request and returns its status/body observation. It does
// NOT capture the full raw response — send is the module's hot loop (dozens of
// probes per host), and only the two identity-B proof requests need the full
// response (see sendProof), so capturing it on every send would allocate a
// headers+body copy that almost every probe discards.
func (m *Module) send(ctx *httpmsg.HttpRequestResponse, client *http.Requester, name, value string) responseObservation {
	return m.sendObservation(ctx, client, name, value, false)
}

// sendProof is send that also captures the full raw response, for the identity-B
// requests whose response becomes the finding's proof (bypassProof.responseB).
func (m *Module) sendProof(ctx *httpmsg.HttpRequestResponse, client *http.Requester, name, value string) responseObservation {
	return m.sendObservation(ctx, client, name, value, true)
}

func (m *Module) sendObservation(ctx *httpmsg.HttpRequestResponse, client *http.Requester, name, value string, captureFull bool) responseObservation {
	raw := ctx.Request().Raw()
	if name != "" {
		var err error
		raw, err = httpmsg.AddOrReplaceHeader(raw, name, value)
		if err != nil {
			return responseObservation{}
		}
	}
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return responseObservation{}
		}
		return responseObservation{}
	}
	defer resp.Close()
	if resp.Response() == nil {
		return responseObservation{}
	}
	obs := responseObservation{
		status: resp.Response().StatusCode,
		body:   resp.Body().String(),
		ok:     true,
	}
	if captureFull {
		obs.fullResponse = resp.FullResponseString()
	}
	return obs
}
