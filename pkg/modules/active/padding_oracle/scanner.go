package padding_oracle

import (
	"fmt"
	"regexp"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// cbcTechTag is the tech tag this module is hard-gated on. It is published by the
// crypto_weakness_detect passive module when it sees a CBC-shaped ciphertext or a
// disclosed padding/decryption error.
const cbcTechTag = "crypto-cbc"

// paddingErrorRe matches the padding/decryption error strings a CBC padding oracle
// leaks. Case-insensitive.
var paddingErrorRe = regexp.MustCompile(`(?i)(BadPaddingException|invalid padding|padding is invalid|padding error|PKCS[#]?[57][^\n]{0,40}(error|invalid|bad)|decryption (failed|error)|CryptographicException|bad decrypt|mac check failed)`)

const (
	// deepSweepValues is the bounded number of last-byte values the deep lane
	// sweeps (the full byte range).
	deepSweepValues = 256
	// deepDominantMin is the minimum size of the invalid-padding cluster the deep
	// sweep must produce to be a credible oracle (a genuine last-byte search yields
	// ~255 invalid vs 1 valid).
	deepDominantMin = 200
	// deepMinorityMax caps the valid-padding cluster size: the valid response must
	// be a small, stable minority, not half the sweep (which would be noise).
	deepMinorityMax = 16
)

// Module implements the CBC padding-oracle confirmer.
type Module struct {
	modkit.BaseActiveModule
}

// New creates a new padding-oracle module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllInsertionPointTypes,
		),
	}
	m.ModuleTags = ModuleTags
	return m
}

// RequiredTechs implements modules.TechAware: the executor only dispatches this
// module against hosts where "crypto-cbc" was detected. The executor gate fails
// OPEN on unknown hosts, so ScanPerInsertionPoint re-checks and fails CLOSED.
func (m *Module) RequiredTechs() []string { return []string{cbcTechTag} }

// ScanPerInsertionPoint confirms a CBC padding oracle at a single insertion point.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	u, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := u.Host

	// HARD tech gate (fail CLOSED): never probe a host that has not been observed
	// to use CBC-shaped crypto. This module sends many mutation requests, so it must
	// not run speculatively on every parameter of every host.
	if !scanCtx.HasTech(host, cbcTechTag) {
		return nil, nil
	}

	// Candidate gate: the value must decode to a block-aligned, high-entropy
	// ciphertext-shaped blob.
	cand, ok := DetectCiphertext(ip.BaseValue())
	if !ok {
		return nil, nil
	}

	// Lane A (explicit-error): always runs. ~7 requests.
	result, err := m.confirmExplicitError(ctx, ip, httpClient, cand)
	if err != nil {
		// Any transport error (including an unresponsive host) means we cannot
		// confirm — abort quietly rather than emit an unconfirmed finding.
		return nil, nil
	}

	// Lane B (behavioral): deep-scan only fallback for oracles that distinguish
	// valid/invalid padding by response shape rather than an explicit error string.
	if result == nil && scanCtx.DeepScan {
		result, err = m.confirmBehavioral(ctx, ip, httpClient, cand)
		if err != nil {
			return nil, nil
		}
	}

	if result == nil {
		return nil, nil
	}
	result.URL = u.String()
	result.Host = host
	result.Matched = u.String()
	return []*output.ResultEvent{result}, nil
}

// probeResult is a single mutation probe's captured response.
type probeResult struct {
	status  int
	body    string
	rawReq  string
	rawResp string
	blocked bool
}

func (pr probeResult) hasPaddingError() bool { return paddingErrorRe.MatchString(pr.body) }

func (pr probeResult) signature() modkit.ResponseSignature {
	return modkit.NewResponseSignature(pr.status, pr.body, "")
}

// clusterKey buckets a response by status and normalized body hash so per-request
// dynamic tokens don't split otherwise-identical responses into separate clusters.
func clusterKey(pr probeResult) string {
	return fmt.Sprintf("%d|%s", pr.status, modkit.NormalizedBodyHash(pr.body))
}

// probe sends value through the insertion point and captures the response. All
// probes run with NoRedirects+NoClustering so each mutation is a genuine origin
// round-trip (a cached/redirected response would defeat the differential).
func (m *Module) probe(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	value string,
) (probeResult, error) {
	raw := ip.BuildRequest([]byte(value))
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return probeResult{}, err
	}
	defer resp.Close()

	pr := probeResult{rawReq: string(raw)}
	if resp.Response() != nil {
		pr.status = resp.Response().StatusCode
	}
	pr.body = resp.BodyString()
	pr.rawResp = resp.FullResponseString()
	pr.blocked = infra.IsBlockedResponse(resp) ||
		modkit.IsEdgeBlockedResponse(httpmsg.NewHttpResponse([]byte(pr.rawResp)))
	return pr, nil
}

// confirmExplicitError is Lane A: it proves the oracle by requiring a padding-
// specific error string that is present in aligned mutations, absent from stable
// baselines, and distinct from a malformed-encoding control — reproduced across
// two rounds at different bit positions.
func (m *Module) confirmExplicitError(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	cand Candidate,
) (*output.ResultEvent, error) {
	original := ip.BaseValue()

	// 1. Two clean baselines with the original ciphertext must be stable, unblocked,
	//    and must NOT already carry a padding error (a valid token that errors is not
	//    an oracle differential).
	base1, err := m.probe(ctx, ip, httpClient, original)
	if err != nil {
		return nil, err
	}
	base2, err := m.probe(ctx, ip, httpClient, original)
	if err != nil {
		return nil, err
	}
	if base1.blocked || base2.blocked {
		return nil, nil
	}
	if modkit.IsDifferent(base1.signature(), base2.signature()) {
		return nil, nil // unstable baseline — a differential cannot be trusted
	}
	if base1.hasPaddingError() || base2.hasPaddingError() {
		return nil, nil
	}

	// 2. Malformed-encoding control: corrupt the ENCODING of the original ciphertext
	//    so it fails to decode BEFORE decryption. It must be unblocked and must NOT
	//    show the padding error (that is the distinct pre-decrypt error class).
	malformed, err := m.probe(ctx, ip, httpClient, MalformedControl(cand.Reencode(cand.Decoded)))
	if err != nil {
		return nil, err
	}
	if malformed.blocked || malformed.hasPaddingError() {
		return nil, nil
	}

	// 3. Two rounds of aligned mutations at DIFFERENT bit positions in the
	//    penultimate block (offsets 1..4; offset 1 is the last/padding byte). Every
	//    mutation must reproduce a padding-specific error and be unblocked. Round 1
	//    (offsets 1,2) must also differ from the malformed-encoding control, rejecting
	//    the "one generic error for everything" collapse.
	muts := make([]probeResult, 4)
	for i, off := range []int{1, 2, 3, 4} {
		mut, err := m.probe(ctx, ip, httpClient, cand.Reencode(FlipPenultimateByteAt(cand.Decoded, cand.BlockSize, off)))
		if err != nil {
			return nil, err
		}
		if mut.blocked || !mut.hasPaddingError() {
			return nil, nil
		}
		if i < 2 && mut.body == malformed.body {
			return nil, nil
		}
		muts[i] = mut
	}

	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline 1 (original ciphertext)", base1.rawReq, base1.rawResp)
	ev.Add("baseline 2 (original ciphertext)", base2.rawReq, base2.rawResp)
	ev.Add("malformed-encoding control (pre-decrypt decode error)", malformed.rawReq, malformed.rawResp)
	for i, mut := range muts {
		ev.Add(fmt.Sprintf("round %d mutation (penultimate byte offset %d)", i/2+1, i+1), mut.rawReq, mut.rawResp)
	}

	return m.buildFinding(ip, cand, "explicit-error", 2, muts[0], ev), nil
}

// confirmBehavioral is Lane B (deep-scan only): it sweeps all 256 values of the
// last byte of the penultimate block and requires a dominant invalid-padding
// cluster, a small stable valid-padding minority, and a separate malformed class —
// then reconfirms the same structure on a second, independent byte.
func (m *Module) confirmBehavioral(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	cand Candidate,
) (*output.ResultEvent, error) {
	dec := cand.Decoded
	penultLastIdx := len(dec) - cand.BlockSize - 1
	if penultLastIdx < 0 {
		return nil, nil
	}

	malformed, err := m.probe(ctx, ip, httpClient, MalformedControl(cand.Reencode(dec)))
	if err != nil {
		return nil, err
	}
	if malformed.blocked {
		return nil, nil
	}
	malformedKey := clusterKey(malformed)

	clusters1, err := m.sweepByte(ctx, ip, httpClient, cand, penultLastIdx)
	if err != nil {
		return nil, err
	}
	dom1, min1, ok := classifySweep(clusters1, malformedKey)
	if !ok {
		return nil, nil
	}

	// Reconfirm on a second, independent byte: the last byte of an earlier block
	// when the ciphertext has three or more blocks, otherwise a different byte of
	// the penultimate block.
	secondIdx := penultLastIdx - cand.BlockSize
	if secondIdx < 0 {
		secondIdx = penultLastIdx - 1
	}
	if secondIdx < 0 || secondIdx == penultLastIdx {
		return nil, nil
	}
	clusters2, err := m.sweepByte(ctx, ip, httpClient, cand, secondIdx)
	if err != nil {
		return nil, err
	}
	if _, _, ok := classifySweep(clusters2, malformedKey); !ok {
		return nil, nil
	}

	ev := modkit.NewEvidenceCollector()
	ev.Add("malformed-encoding control (separate decode-error class)", malformed.rawReq, malformed.rawResp)
	ev.Add(fmt.Sprintf("dominant invalid-padding cluster (%d/%d)", dom1.count, deepSweepValues), dom1.rep.rawReq, dom1.rep.rawResp)
	ev.Add(fmt.Sprintf("minority valid-padding cluster (%d/%d)", min1.count, deepSweepValues), min1.rep.rawReq, min1.rep.rawResp)

	return m.buildFinding(ip, cand, "behavioral", 2, dom1.rep, ev), nil
}

// sweepCluster accumulates the responses that share a cluster key.
type sweepCluster struct {
	rep   probeResult
	count int
}

// sweepByte sends all 256 values of the byte at idx and clusters the responses.
// It returns a nil map (with a nil error) if a probe is blocked — a blocked sweep
// cannot be trusted. hosterrors/transport errors propagate to the caller.
func (m *Module) sweepByte(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	cand Candidate,
	idx int,
) (map[string]*sweepCluster, error) {
	if idx < 0 || idx >= len(cand.Decoded) {
		return nil, nil
	}
	clusters := make(map[string]*sweepCluster)
	// One reusable buffer for the 256-value sweep: Reencode copies its input into a
	// fresh string, so mutating buf[idx] in place between probes is safe.
	buf := append([]byte(nil), cand.Decoded...)
	for v := 0; v < deepSweepValues; v++ {
		buf[idx] = byte(v)
		pr, err := m.probe(ctx, ip, httpClient, cand.Reencode(buf))
		if err != nil {
			return nil, err
		}
		if pr.blocked {
			return nil, nil
		}
		key := clusterKey(pr)
		c := clusters[key]
		if c == nil {
			c = &sweepCluster{rep: pr}
			clusters[key] = c
		}
		c.count++
	}
	return clusters, nil
}

// classifySweep verifies the padding-oracle cluster structure: a dominant
// (invalid-padding) cluster distinct from the malformed class, plus a small stable
// (valid-padding) minority cluster.
func classifySweep(clusters map[string]*sweepCluster, malformedKey string) (dominant, minority *sweepCluster, ok bool) {
	if len(clusters) < 2 {
		return nil, nil, false
	}
	var dominantKey string
	for key, c := range clusters {
		if dominant == nil || c.count > dominant.count {
			dominant, dominantKey = c, key
		}
	}
	if dominant == nil || dominant.count < deepDominantMin {
		return nil, nil, false
	}
	if dominantKey == malformedKey {
		return nil, nil, false // the majority IS the decode-error class — not an oracle
	}
	for key, c := range clusters {
		if c == dominant || key == malformedKey {
			continue
		}
		if c.count >= 1 && c.count <= deepMinorityMax {
			if minority == nil || c.count < minority.count {
				minority = c
			}
		}
	}
	if minority == nil {
		return nil, nil, false
	}
	return dominant, minority, true
}

// buildFinding assembles the High/Firm padding-oracle result.
func (m *Module) buildFinding(
	ip httpmsg.InsertionPoint,
	cand Candidate,
	lane string,
	rounds int,
	proof probeResult,
	ev *modkit.EvidenceCollector,
) *output.ResultEvent {
	desc := fmt.Sprintf(
		"Confirmed a CBC padding oracle in parameter %q. The %s-encoded, %d-byte "+
			"block-aligned ciphertext was mutated in the penultimate block and the "+
			"target reproducibly revealed padding validity (lane: %s) across %d "+
			"independent rounds, while a malformed-encoding control produced a distinct "+
			"pre-decrypt error class. An attacker can decrypt or forge this ciphertext "+
			"byte-by-byte without the key.",
		ip.Name(), cand.Encoding.String(), len(cand.Decoded), lane, rounds)

	return &output.ResultEvent{
		ModuleID:           ModuleID,
		Request:            proof.rawReq,
		Response:           proof.rawResp,
		FuzzingParameter:   ip.Name(),
		MatcherStatus:      true,
		AdditionalEvidence: ev.Entries(),
		ExtractedResults: []string{
			fmt.Sprintf("encoding=%s", cand.Encoding.String()),
			fmt.Sprintf("block_size=%d", cand.BlockSize),
			fmt.Sprintf("lane=%s", lane),
		},
		Info: output.Info{
			Name:        ModuleName,
			Description: desc,
			Severity:    severity.High,
			Confidence:  severity.Firm,
		},
		Metadata: map[string]any{
			"encoding":        cand.Encoding.String(),
			"block_size":      cand.BlockSize,
			"lane":            lane,
			"rounds":          rounds,
			"insertion_point": ip.Name(),
		},
	}
}
