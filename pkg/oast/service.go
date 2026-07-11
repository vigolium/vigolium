package oast

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	interactshclient "github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// PayloadContext stores context about an injected OAST payload for correlation.
type PayloadContext struct {
	TargetURL     string
	ParameterName string
	InjectionType string
	ModuleID      string
	RequestHash   string
	// CallbackURL is the unique OAST URL that was planted (the payload the target
	// called back to). Retained so the finding can show exactly what was injected.
	CallbackURL string
	// Payload is the literal value the planting module placed at the injection
	// point (e.g. ";nslookup <host>" for command injection, "for=<host>" for an
	// RFC 7239 Forwarded probe, the bare "<host>" for an IP-routing header). It is
	// what was actually sent on the wire, so the finding can reconstruct the
	// planting request faithfully instead of guessing an http://<host> shape.
	// Modules that mint a unique callback host per payload variant (e.g. the
	// command-injection modules now plant one OAST host per breakout shape) record
	// the exact variant here, so a callback pinpoints the precise payload that fired.
	// Set via RecordPayload after the host is known; empty for modules that do not
	// record it (reconstruction then falls back to the http://<host> / bare-host
	// shape).
	Payload string
}

// oastTrackerCacheSize bounds the nonce → PayloadContext tracker. A plain
// sync.Map here grew unbounded: every planted payload added an entry that was
// never deleted, so over a long-lived OAST-enabled scan (records × OAST-capable
// insertion points) it was the fastest-growing map of all. A bounded LRU caps
// it; a callback for a given payload almost always arrives within the grace
// period, long before this many newer payloads would evict it, so correlation
// fidelity is preserved for any payload still in flight.
const oastTrackerCacheSize = 65536

// Service wraps an interactsh client with payload tracking and result emission.
type Service struct {
	client             *interactshclient.Client
	trackerOnce        sync.Once
	tracker            *lru.Cache[string, PayloadContext] // nonce → PayloadContext (bounded LRU)
	emitResult         func(*output.ResultEvent)
	resolveRequestUUID func(requestHash string) string // resolves request hash → DB record UUID
	repo               *database.Repository
	scanUUID           string
	projectUUID        string
	pollInterval       time.Duration
	gracePeriod        time.Duration
	serverURL          string // interactsh server hostname (e.g. "oast.pro")
	fixedURL           string // when set, skip interactsh and use this URL directly
	blindXSSSrc        string // JS script src for blind XSS payloads
	enabledBlindXSS    bool   // whether blind XSS probing is active

	// emitMu guards emittedRank, the finding-coalescing state. A single planted
	// payload typically produces several callbacks — DNS A + AAAA, multiple recursive
	// resolvers hitting the authoritative server, then the HTTP fetch leg — and
	// without coalescing each became its own finding sharing one callback host.
	// emittedRank maps an emission key to the strongest protocol rank already turned
	// into a finding, so duplicate/weaker callbacks are folded into the existing
	// finding and a strictly stronger callback upgrades it in place (see
	// claimEmission). The key is the callback nonce for high-signal interactions and
	// module+host+injection point for low-signal Info ones (see oastEmissionKey), so
	// Info findings additionally coalesce across the many URLs that plant the same
	// injection point on a host. Only keys that actually call back get an entry, so
	// this stays small (unlike the every-payload tracker) and needs no eviction.
	emitMu      sync.Mutex
	emittedRank map[string]int // emission key → strongest OAST protocol rank already emitted
}

// New creates a new OAST service. Returns (nil, nil) if the interactsh client
// cannot be created — callers should treat nil as "OAST unavailable" and continue.
// resolveRequestUUID is an optional function that maps a request hash to a database
// record UUID, enabling Finding records to be linked to their originating HTTP records.
func New(cfg *config.OASTConfig, emitResult func(*output.ResultEvent), repo *database.Repository, scanUUID string, projectUUID string, resolveRequestUUID func(string) string) (*Service, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	// Fixed URL mode: skip interactsh client entirely
	if cfg.OastURL != "" {
		return &Service{
			fixedURL:           cfg.OastURL,
			emitResult:         emitResult,
			resolveRequestUUID: resolveRequestUUID,
			repo:               repo,
			scanUUID:           scanUUID,
			projectUUID:        projectUUID,
			blindXSSSrc:        cfg.BlindXSSSrc,
			enabledBlindXSS:    cfg.EnabledBlindXSS,
		}, nil
	}

	serverURL := cfg.ServerURL
	if serverURL == "" {
		serverURL = "oast.pro"
	}

	opts := &interactshclient.Options{
		ServerURL: serverURL,
		Token:     cfg.Token,
	}

	client, err := interactshclient.New(opts)
	if err != nil {
		zap.L().Warn("OAST: failed to create interactsh client, continuing without OAST",
			zap.String("server", serverURL),
			zap.Error(err))
		return nil, nil
	}

	pollInterval := time.Duration(cfg.PollInterval) * time.Second
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	gracePeriod := time.Duration(cfg.GracePeriod) * time.Second
	if gracePeriod <= 0 {
		gracePeriod = 10 * time.Second
	}

	return &Service{
		client:             client,
		serverURL:          serverURL,
		emitResult:         emitResult,
		resolveRequestUUID: resolveRequestUUID,
		repo:               repo,
		scanUUID:           scanUUID,
		projectUUID:        projectUUID,
		pollInterval:       pollInterval,
		gracePeriod:        gracePeriod,
		blindXSSSrc:        cfg.BlindXSSSrc,
		enabledBlindXSS:    cfg.EnabledBlindXSS,
	}, nil
}

// ServerURL returns the interactsh server hostname (e.g. "oast.pro").
func (s *Service) ServerURL() string {
	if s == nil {
		return ""
	}
	if s.fixedURL != "" {
		return s.fixedURL
	}
	return s.serverURL
}

// Start begins polling the interactsh server for interactions.
func (s *Service) Start() {
	if s == nil || s.client == nil {
		return
	}

	if err := s.client.StartPolling(s.pollInterval, s.handleInteraction); err != nil {
		zap.L().Warn("OAST: failed to start polling", zap.Error(err))
	}

	zap.L().Info("OAST: polling started",
		zap.Duration("interval", s.pollInterval),
		zap.Duration("grace_period", s.gracePeriod))
}

// trackerCache lazily initializes the bounded payload tracker so a zero-value
// &Service{} (used by tests) stays safe.
func (s *Service) trackerCache() *lru.Cache[string, PayloadContext] {
	s.trackerOnce.Do(func() {
		// lru.New only errors on size <= 0; the constant is positive.
		s.tracker, _ = lru.New[string, PayloadContext](oastTrackerCacheSize)
	})
	return s.tracker
}

// GenerateURL creates a unique OAST callback URL and tracks the payload context.
func (s *Service) GenerateURL(targetURL, paramName, injectionType, moduleID, requestHash string) string {
	if s == nil {
		return ""
	}

	// Fixed URL mode: return the configured URL directly (no nonce tracking)
	if s.fixedURL != "" {
		return s.fixedURL
	}

	if s.client == nil {
		return ""
	}

	url := s.client.URL()
	if url == "" {
		return ""
	}

	// Extract nonce from the URL: format is "correlationID+nonce.server.host"
	// The nonce is everything before the first dot minus the correlation ID prefix.
	// We use the full subdomain (before first dot) as the tracker key.
	nonce := extractNonce(url)
	if nonce != "" {
		s.trackerCache().Add(nonce, PayloadContext{
			TargetURL:     targetURL,
			ParameterName: paramName,
			InjectionType: injectionType,
			ModuleID:      moduleID,
			RequestHash:   requestHash,
			CallbackURL:   url,
		})
	}

	return url
}

// RecordPayload attaches the literal value a module planted at its injection
// point to the tracked context for callbackURL, so the resulting finding can
// reconstruct the planting request faithfully (see PayloadContext.Payload).
// callbackURL is the URL returned by GenerateURL; payload is the exact value
// written at the injection point (header value, parameter value, …). A no-op
// when OAST is in fixed-URL mode or the context has already been evicted.
func (s *Service) RecordPayload(callbackURL, payload string) {
	if s == nil || s.client == nil || callbackURL == "" || payload == "" {
		return
	}
	nonce := extractNonce(callbackURL)
	if nonce == "" {
		return
	}
	cache := s.trackerCache()
	pctx, ok := cache.Get(nonce)
	if !ok {
		return
	}
	pctx.Payload = payload
	cache.Add(nonce, pctx)
}

// Enabled returns true if the OAST service is active.
func (s *Service) Enabled() bool {
	return s != nil && (s.client != nil || s.fixedURL != "")
}

// BlindXSSSrc returns the configured blind XSS script src URL.
func (s *Service) BlindXSSSrc() string {
	if s == nil {
		return ""
	}
	return s.blindXSSSrc
}

// BlindXSSEnabled returns whether blind XSS probing is enabled.
func (s *Service) BlindXSSEnabled() bool {
	return s != nil && s.enabledBlindXSS
}

// SetRequestUUIDResolver updates the function used to resolve request hashes
// to database record UUIDs. Called when a new executor is created (e.g., per
// scan round) so that OAST callbacks can be linked to the correct HTTP records.
func (s *Service) SetRequestUUIDResolver(fn func(string) string) {
	if s == nil {
		return
	}
	s.resolveRequestUUID = fn
}

// Flush waits for the grace period and then performs a final poll to catch late callbacks.
func (s *Service) Flush() {
	if s == nil || s.client == nil {
		return
	}

	zap.L().Info("OAST: grace period started, waiting for late callbacks",
		zap.Duration("grace_period", s.gracePeriod))
	time.Sleep(s.gracePeriod)
}

// Close stops polling and deregisters from the interactsh server.
func (s *Service) Close() {
	if s == nil || s.client == nil {
		return
	}

	if err := s.client.Close(); err != nil {
		zap.L().Debug("OAST: error closing client", zap.Error(err))
	}
}

// handleInteraction processes a single interaction from the interactsh server.
func (s *Service) handleInteraction(interaction *server.Interaction) {
	if interaction == nil {
		return
	}

	// Look up payload context using the unique ID
	nonce := interaction.UniqueID
	pctx, found := s.trackerCache().Get(nonce)

	// Debug, not Info: a single planted payload fans out into ~5-6 callbacks
	// (DNS A/AAAA, several recursive resolvers, then the HTTP leg), so logging
	// every callback at Info floods the log even though only one emits a finding.
	zap.L().Debug("OAST: interaction received",
		zap.String("protocol", interaction.Protocol),
		zap.String("unique_id", interaction.UniqueID),
		zap.String("remote_addr", interaction.RemoteAddress),
		zap.Bool("correlated", found))

	// Save to database
	if s.repo != nil {
		record := &database.OASTInteraction{
			ProjectUUID:   s.projectUUID,
			ScanUUID:      s.scanUUID,
			UniqueID:      interaction.UniqueID,
			FullID:        interaction.FullId,
			Protocol:      interaction.Protocol,
			QType:         interaction.QType,
			RawRequest:    interaction.RawRequest,
			RawResponse:   interaction.RawResponse,
			RemoteAddress: interaction.RemoteAddress,
			InteractedAt:  interaction.Timestamp,
			TargetURL:     pctx.TargetURL,
			ParameterName: pctx.ParameterName,
			InjectionType: pctx.InjectionType,
			ModuleID:      pctx.ModuleID,
			Payload:       pctx.CallbackURL,
		}
		if err := s.repo.SaveOASTInteraction(context.Background(), record); err != nil {
			zap.L().Warn("OAST: failed to save interaction", zap.Error(err))
		}
	}

	// Only emit finding if we have correlation context
	if !found {
		return
	}

	// Classify first (cheap, no I/O) so the emission key can depend on severity.
	sev, conf, desc := classifyInteraction(interaction.Protocol, pctx)

	// Second-signal confirmation. A correlated hit on the unguessable per-payload
	// subdomain proves the injected http://<oast> URL was reached — but not
	// necessarily by the vulnerability firing. URL-preview bots, site-monitoring
	// crawlers, and WAF/threat-intel enrichment routinely harvest an injected URL
	// from request logs (or a feed) and fetch it later with a browser/crawler HTTP
	// client; that callback correlates to the nonce yet has nothing to do with the
	// vuln. refineOASTCallback inspects the raw callback request and downgrades to an
	// unconfirmed lead when it bears fingerprints the vuln's real out-of-band fetcher
	// never has, so the classic harvested-URL OAST false positive (blind XXE/SQLi/JWT
	// and, narrowly, SSRF) no longer surfaces as a Certain High finding. Runs before
	// the emission key is derived because it can change the severity (Low/Info are
	// still handled by oastEmissionKey — a Low keeps per-nonce identity).
	sev, conf, desc = refineOASTCallback(interaction, pctx, sev, conf, desc)

	emitKey := oastEmissionKey(sev, nonce, pctx)

	// Coalesce per emission key. A single planted payload fans out into many
	// callbacks (DNS A/AAAA, several recursive resolvers, then the HTTP fetch leg);
	// and — for low-signal Info interactions — a crawler plants the same injection
	// point across dozens of URLs on one host (e.g. a Referer the target logs and
	// resolves), producing one near-identical DNS-only finding per URL. Emit at most
	// one finding per emission key — folding duplicate/weaker callbacks into it and
	// upgrading in place when a strictly stronger protocol confirms it — so the
	// findings list shows one entry per OAST host (or, for Info, per host+injection
	// point), not a pile.
	emit, upgrade := s.claimEmission(emitKey, interaction.Protocol)
	if !emit {
		return
	}

	// Recover the request that planted the payload so both the finding's trace
	// anchors and its DB link resolve without a manual join. Done only after the
	// emit gate: this loads up to two full request/response blobs, and only one
	// of a payload's ~5-6 callbacks ever reaches here.
	originUUID, origin := s.originRecord(pctx.RequestHash)

	result := &output.ResultEvent{
		ModuleID: pctx.ModuleID,
		URL:      pctx.TargetURL,
		Matched:  pctx.TargetURL,
		Info: output.Info{
			Name:        "Out-of-Band Interaction Detected",
			Description: desc,
			Severity:    sev,
			Confidence:  conf,
		},
		ExtractedResults: []string{
			"protocol=" + interaction.Protocol,
			"oast_id=" + interaction.UniqueID,
			"remote_addr=" + interaction.RemoteAddress,
		},
		FuzzingParameter: pctx.ParameterName,
		MatcherStatus:    true,
		ModuleType:       database.ModuleTypeOAST,
		FindingSource:    database.FindingSourceOAST,
		ModuleShort:      "Out-of-band interaction detected via OAST callback",
		// Identify the finding by its emission key — the callback nonce for high-signal
		// interactions (each distinct payload host is its own finding, re-callbacks
		// dedup), or module+host+injection-point for low-signal Info interactions (all
		// equivalent URLs collapse to one) — independent of the protocol-driven
		// description/severity that an upgrade changes.
		DedupKey: "oast:" + emitKey,
	}

	// Attach the originating request and human-readable trace anchors so the
	// finding answers "which request caused this callback?" on its own.
	enrichOASTResult(result, interaction, pctx, origin)

	// A coalesced Info finding stands in for every equivalent URL on the host, so
	// make the aggregation explicit — otherwise the single entry (and its one linked
	// request) reads as a lone observation. The raw oast_interactions table still
	// records every callback for forensics.
	if sev == severity.Info {
		result.ExtractedResults = append(result.ExtractedResults,
			"scope=host-aggregated (Info OAST interactions coalesced per host + injection point; see oast_interactions for every callback)")
	}

	// On an upgrade (e.g. the HTTP-fetch confirmation arriving after a DNS lead) the
	// stronger finding shares the weaker one's nonce-scoped hash, so INSERT-ON-
	// CONFLICT would keep the weaker row. Drop it first so the stronger one replaces
	// it and the payload still yields exactly one finding.
	if upgrade && s.repo != nil {
		if err := s.repo.DeleteFindingByHash(context.Background(), s.projectUUID, result.ID()); err != nil {
			zap.L().Warn("OAST: failed to replace weaker finding on upgrade", zap.Error(err))
		}
	}

	// Save finding to database, linked to the originating HTTP record
	s.saveFinding(result, originUUID)

	if s.emitResult != nil {
		s.emitResult(result)
	}
}

// oastProtocolRank ranks an OAST callback protocol by how strongly it proves the
// underlying vulnerability, so a later, stronger callback for the same payload can
// upgrade the existing finding instead of spawning a duplicate. An HTTP(S) callback
// (an actual outbound fetch) is the strongest signal; DNS (mere resolution) is the
// weakest; any other protocol sits in between.
func oastProtocolRank(proto string) int {
	switch strings.ToLower(proto) {
	case "http", "https":
		return 3
	case "dns":
		return 1
	default:
		return 2
	}
}

// claimEmission records that a callback of protocol proto arrived for emission
// key key and decides whether it should produce (or upgrade) a finding:
//
//   - first callback for a key → (emit=true, upgrade=false): emit a new finding.
//   - duplicate or weaker-or-equal callback for a key already reported (the DNS
//     A/AAAA/resolver flood, or a DNS hit after the HTTP leg) → (false, false):
//     fold into the existing finding, emit nothing.
//   - strictly stronger callback than what was already reported (e.g. the HTTP fetch
//     confirming an earlier DNS lead) → (true, true): the caller replaces the weaker
//     finding with this stronger one.
//
// The key is the callback nonce for high-signal interactions and a coalescing
// key (module+host+injection point) for low-signal Info ones — see
// oastEmissionKey — so Info findings collapse per host+injection point while
// confirmed findings keep per-request granularity.
func (s *Service) claimEmission(key, proto string) (emit, upgrade bool) {
	rank := oastProtocolRank(proto)
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	if s.emittedRank == nil {
		s.emittedRank = make(map[string]int)
	}
	prev, seen := s.emittedRank[key]
	if seen && rank <= prev {
		return false, false
	}
	s.emittedRank[key] = rank
	return true, seen
}

// oastEmissionKey chooses the coalescing identity for an out-of-band finding.
//
// High-signal interactions (a confirmed HTTP fetch, or an XXE/SQLi/JWT DNS hit on
// an unguessable per-payload subdomain — all rated above Info) keep per-callback-
// nonce identity, so every distinct planting request stays its own investigable
// finding.
//
// Low-signal Info interactions — the generic blind-SSRF DNS-only lead and the
// host-header-reflection case, both of which classifyInteraction rates Info — are
// coalesced per (module, host, injection point). A crawler hits dozens of URLs on
// one host, each planting the same injection point (commonly a Referer the target
// logs and its resolver looks up), so without this every URL yields a near-
// identical DNS-only finding. At this severity the injection point and host are the
// whole signal; which of N equivalent URLs planted it is not — so they fold into
// one finding (the raw oast_interactions table still records every callback).
func oastEmissionKey(sev severity.Severity, nonce string, pctx PayloadContext) string {
	if sev != severity.Info {
		return nonce
	}
	param := strings.ToLower(strings.TrimSpace(pctx.ParameterName))
	return pctx.ModuleID + "|" + oastHost(pctx.TargetURL) + "|" + param
}

// oastHost extracts the lowercased host[:port] from a target URL for coalescing;
// on a parse failure or a hostless URL it falls back to the raw (trimmed, lowered)
// string so distinct targets never collide onto one key.
func oastHost(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return strings.ToLower(u.Host)
	}
	return strings.ToLower(strings.TrimSpace(target))
}

// originRecord resolves the HTTP record that planted an OAST payload. It prefers
// the executor's in-memory hash→UUID resolver, then loads the record from the
// database; if the resolver is empty (a late callback after the executor is gone)
// it falls back to a request-hash lookup. Returns the record UUID — which may be
// non-empty even when the body could not be loaded — and the record (may be nil).
func (s *Service) originRecord(requestHash string) (string, *database.HTTPRecord) {
	if requestHash == "" {
		return "", nil
	}
	var uuid string
	if s.resolveRequestUUID != nil {
		uuid = s.resolveRequestUUID(requestHash)
	}
	if s.repo == nil {
		return uuid, nil
	}
	ctx := context.Background()
	if uuid != "" {
		if rec, err := s.repo.GetRecordByUUID(ctx, uuid); err == nil && rec != nil {
			return uuid, rec
		}
	}
	// Fallback: recover by request hash (the in-memory resolver may be gone).
	if rec, err := s.repo.GetRecordByRequestHash(ctx, s.projectUUID, requestHash); err == nil && rec != nil {
		return rec.UUID, rec
	}
	return uuid, nil
}

// enrichOASTResult embeds the originating request/response and trace anchors into
// an out-of-band finding so it can be traced back to the request that planted the
// payload without a manual database join. origin may be nil.
func enrichOASTResult(result *output.ResultEvent, interaction *server.Interaction, pctx PayloadContext, origin *database.HTTPRecord) {
	if pctx.CallbackURL != "" {
		result.ExtractedResults = append(result.ExtractedResults, "callback_url="+pctx.CallbackURL)
		// State the planted payload and its injection point explicitly, so plain-text
		// outputs answer "what was injected, and where?" even when no request panel
		// is rendered.
		result.ExtractedResults = append(result.ExtractedResults,
			"injected_payload="+describeInjectedPayload(pctx, interaction.Protocol))
	}

	if origin != nil {
		originLine := strings.TrimSpace(origin.Method + " " + origin.URL)
		if origin.UUID != "" {
			result.ExtractedResults = append(result.ExtractedResults, "http_record="+origin.UUID)
		}
		if originLine != "" {
			result.ExtractedResults = append(result.ExtractedResults, "origin_request="+originLine)
		}
		// Embed the planting request with the OAST payload re-applied at its
		// injection point, so the Request panel shows where the callback URL was
		// planted. The raw modified request that fired the callback is not retained
		// (correlation is keyed by the original request's hash); payloadRequest
		// reconstructs it from the original request plus the payload context.
		if len(origin.RawRequest) > 0 {
			result.Request = payloadRequest(origin.RawRequest, pctx, interaction.Protocol)
		}
		if len(origin.RawResponse) > 0 {
			result.Response = string(origin.RawResponse)
		}
		// Fold the same anchors into the description so plain-text outputs
		// (console, JSONL) are self-describing too.
		if originLine != "" {
			result.Info.Description += " Originating request: " + originLine
			if origin.UUID != "" {
				result.Info.Description += " (http_record " + origin.UUID + ")"
			}
			result.Info.Description += "."
		}
	}

	if !interaction.Timestamp.IsZero() {
		result.ExtractedResults = append(result.ExtractedResults,
			"interacted_at="+interaction.Timestamp.UTC().Format(time.RFC3339))
	}

	// The raw out-of-band request the target's infrastructure sent to the
	// collaborator — direct, unforgeable proof of the callback — kept as evidence.
	if cb := strings.TrimSpace(interaction.RawRequest); cb != "" {
		label := "oast-callback (" + interaction.Protocol
		if interaction.RemoteAddress != "" {
			label += " from " + interaction.RemoteAddress
		}
		label += ")"
		if ev := output.BuildEvidence(label, interaction.RawRequest, interaction.RawResponse); ev != "" {
			result.AdditionalEvidence = append(result.AdditionalEvidence, ev)
		}
	}
}

// payloadRequest re-applies the OAST payload onto a copy of the original request
// at its injection point, so the finding's Request panel shows where the callback
// URL was planted rather than the bare original. It reconstructs the two
// deterministic injection forms faithfully — request-line targets (routing-based
// SSRF, written verbatim on the request line while the Host header stays the
// victim) and header injections — and otherwise returns the original request
// unchanged (the injected_payload / callback_url anchors still record the
// payload). proto is the callback protocol (http/https).
func payloadRequest(raw []byte, pctx PayloadContext, proto string) string {
	host := callbackHost(pctx.CallbackURL)
	if len(raw) == 0 || host == "" {
		return string(raw)
	}

	switch {
	case strings.EqualFold(pctx.ParameterName, "request-line"):
		return rewriteRequestTarget(raw, callbackScheme(proto)+"://"+host+"/")
	case isHeaderInjection(pctx):
		// Prefer the exact value the module planted (e.g. ";nslookup <host>",
		// "for=<host>", a bare "<host>") so the Request panel shows what really
		// went on the wire; fall back to the http://<host> shape only when the
		// module did not record a payload.
		value := pctx.Payload
		if value == "" {
			value = "http://" + host
		}
		if out, err := httpmsg.AddOrReplaceHeader(raw, pctx.ParameterName, value); err == nil {
			return string(out)
		}
	}
	return string(raw)
}

// describeInjectedPayload renders a one-line "<payload> (<where>)" summary of the
// planted OAST payload for the injected_payload anchor. It states the exact value
// the module planted when one was recorded (PayloadContext.Payload) — so a
// command-injection finding shows ";nslookup <host>" rather than the bare host —
// and falls back to the http://<host> / bare-host shape otherwise. The recorded
// payload is rendered on one line (control characters escaped) so smuggling
// payloads carrying literal CR/LF/space cannot break the anchor.
func describeInjectedPayload(pctx PayloadContext, proto string) string {
	host := callbackHost(pctx.CallbackURL)
	payload := oneLinePayload(pctx.Payload)
	switch {
	case strings.EqualFold(pctx.ParameterName, "request-line"):
		return payloadOr(payload, callbackScheme(proto)+"://"+host+"/", " (request-line)")
	case isHeaderInjection(pctx):
		return payloadOr(payload, "http://"+host, " (header "+pctx.ParameterName+")")
	case pctx.ParameterName != "":
		return payloadOr(payload, host, " (parameter "+pctx.ParameterName+")")
	default:
		return payloadOr(payload, host, "")
	}
}

// payloadOr renders "<payload><suffix>" when the module recorded the exact
// planted payload, falling back to "<fallback><suffix>" otherwise.
func payloadOr(payload, fallback, suffix string) string {
	if payload != "" {
		return payload + suffix
	}
	return fallback + suffix
}

// oneLineReplacer escapes the control characters (CR, LF, tab) that some OAST
// payloads carry literally — most notably the SSRF protocol-smuggling templates.
var oneLineReplacer = strings.NewReplacer("\r", `\r`, "\n", `\n`, "\t", `\t`)

// oneLinePayload renders a recorded payload as a single, readable line in the
// injected_payload anchor so it never injects raw newlines into plain-text output.
func oneLinePayload(s string) string {
	return oneLineReplacer.Replace(s)
}

// isHeaderInjection reports whether the payload was planted in a named request
// header (oast_probe, log4shell/command-injection header legs, internal-header
// probe, …). The injection-type label carries "header" for every such module.
func isHeaderInjection(pctx PayloadContext) bool {
	return pctx.ParameterName != "" && strings.Contains(strings.ToLower(pctx.InjectionType), "header")
}

// callbackHost strips any scheme/path from a stored callback URL, returning the
// bare collaborator host. The interactsh client URL is normally a bare host, but
// the fixed-URL mode may carry a scheme — normalize both.
func callbackHost(callbackURL string) string {
	h := strings.TrimPrefix(callbackURL, "https://")
	h = strings.TrimPrefix(h, "http://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	return h
}

// callbackScheme normalizes the interaction protocol to an http(s) URL scheme,
// defaulting to https for any non-HTTP protocol.
func callbackScheme(proto string) string {
	if scheme := strings.ToLower(proto); scheme == "http" || scheme == "https" {
		return scheme
	}
	return "https"
}

// rewriteRequestTarget returns raw with its request-line target replaced by
// target, preserving the original method, HTTP version, and all headers. This is
// the request-line SSRF wire form: an absolute-URI target while the connection
// and Host header remain the victim.
func rewriteRequestTarget(raw []byte, target string) string {
	s := string(raw)
	nl := strings.IndexByte(s, '\n')
	if nl < 0 {
		return s
	}
	firstLine := strings.TrimRight(s[:nl], "\r")
	rest := s[nl+1:]

	method, version := "GET", "HTTP/1.1"
	if parts := strings.Fields(firstLine); len(parts) > 0 {
		method = parts[0]
		if len(parts) >= 3 {
			version = parts[len(parts)-1]
		}
	}
	return method + " " + target + " " + version + "\r\n" + rest
}

// saveFinding persists a Finding to the database, linked to the originating HTTP
// record when one was resolved (recordUUID may be empty — the finding is still
// saved so out-of-band hits are never silently dropped).
func (s *Service) saveFinding(result *output.ResultEvent, recordUUID string) {
	if s.repo == nil || result == nil {
		return
	}

	var recordUUIDs []string
	if recordUUID != "" {
		recordUUIDs = append(recordUUIDs, recordUUID)
	}

	if err := s.repo.SaveFinding(context.Background(), result, recordUUIDs, s.scanUUID, s.projectUUID); err != nil {
		zap.L().Warn("OAST: failed to save finding to database", zap.Error(err))
	}
}

// classifyInteraction determines severity, confidence, and description based on
// protocol. Confidence defaults to Certain for the existing SSRF/XXE branches
// (an out-of-band callback to an unguessable subdomain is, by itself, proof the
// interaction happened); the command-injection branch returns a calibrated
// confidence because a DNS-only callback there is not always proof of execution.
func classifyInteraction(protocol string, pctx PayloadContext) (severity.Severity, severity.Confidence, string) {
	proto := strings.ToLower(protocol)

	injectionDesc := pctx.InjectionType
	if pctx.ParameterName != "" {
		injectionDesc += " via parameter " + pctx.ParameterName
	}

	// Command-injection OAST payloads (nslookup/ping/curl/wget of a unique,
	// unguessable subdomain) carry a different meaning than the generic SSRF/XXE
	// interpretation: an HTTP-fetch callback means a shell command actually ran.
	// A DNS-only callback is weaker and, on client-IP/forwarding headers, an
	// outright false positive — see classifyCommandInjection.
	if strings.Contains(strings.ToLower(pctx.InjectionType), "command") {
		return classifyCommandInjection(proto, pctx, injectionDesc)
	}

	// XXE payloads (an external DTD / external entity pointing at a unique,
	// unguessable OAST subdomain) mean the target's XML parser resolved the
	// injected reference — unforgeable proof the parser loads external entities.
	// A DNS-only hit is high-confidence here (unlike the generic SSRF case)
	// because the per-payload subdomain rules out coincidental resolution.
	if strings.Contains(strings.ToLower(pctx.InjectionType), "xxe") {
		return classifyXXE(proto, injectionDesc)
	}

	// SQLi out-of-band payloads (MySQL LOAD_FILE of a UNC path, MSSQL xp_dirtree,
	// Oracle UTL_INADDR/UTL_HTTP, PostgreSQL COPY ... TO PROGRAM) make the database
	// itself resolve or fetch a unique, unguessable OAST subdomain. A correlated
	// callback means the injected SQL executed inside the query — proof of blind SQL
	// injection, not SSRF, so it gets its own classifier.
	if strings.Contains(strings.ToLower(pctx.InjectionType), "sql") {
		return classifySQLi(proto, injectionDesc)
	}

	// JWT header key-URL injection (jku/x5u pointing at a unique OAST subdomain):
	// a callback means the server dereferenced an attacker-controlled URL from the
	// token header to fetch a verification key — the precursor to signing-key
	// injection (full auth bypass), and at minimum a server-side request forgery.
	if strings.Contains(strings.ToLower(pctx.InjectionType), "jwt") {
		return classifyJWT(proto, injectionDesc)
	}

	// Host-routing / host-reflection SSRF — request-line manipulation
	// (routing-ssrf) and the proxy-reflected host-header family (X-Forwarded-Host,
	// X-Forwarded-Server, X-Host, X-Original-Host, X-Original-URL, X-Rewrite-URL) —
	// is frequently low-impact AND false-positive-prone: a reverse proxy reflects
	// the value into a redirect Location / upstream URL that the proxy (or a
	// redirect-following client, including the scanner itself) then fetches, so the
	// "outbound HTTP request" is not necessarily a server-side SSRF and rarely
	// reaches anything exploitable. Its OAST callbacks are reported as informational
	// rather than high. Scoped narrowly via the shared isProxyReflectedHostHeader
	// set: genuine parameter-based blind SSRF and the client-IP / non-reflected
	// forwarding headers (X-Forwarded-For, Referer, Origin, …) stay high. The
	// routing_ssrf module ID is matched as a string literal to avoid an import cycle
	// (it imports this package); the header name is matched case-insensitively.
	hostRoutingSSRF := pctx.ModuleID == "routing-ssrf" || isProxyReflectedHostHeader(pctx.ParameterName)
	if hostRoutingSSRF && (proto == "http" || proto == "https") {
		return severity.Info, severity.Certain, "Blind SSRF / host-header reflection: an outbound HTTP request reached the OAST server for a value placed on the request line or a proxy-reflected host header (" + injectionDesc +
			"). Reverse proxies commonly reflect these into a redirect Location / upstream URL that the proxy (or a redirect-following client) then fetches, so impact is usually low and this is often not a server-side SSRF — reported as informational."
	}

	switch proto {
	case "http", "https":
		return severity.High, severity.Certain, "Blind SSRF confirmed: target made outbound HTTP request to OAST server (" + injectionDesc + ")"
	case "dns":
		return severity.Info, severity.Tentative, "DNS interaction detected: target resolved OAST domain (" + injectionDesc + "). May indicate blind SSRF/XXE but DNS alone is lower confidence."
	default:
		return severity.Medium, severity.Certain, "Out-of-band " + protocol + " interaction detected (" + injectionDesc + ")"
	}
}

// classifyXXE rates out-of-band interactions triggered by an injected external
// DTD/entity. The per-payload subdomain is random and unguessable, so a
// correlated callback proves the injected URL was reached. Whether an XML parser
// reached it — versus a crawler that harvested the injected URL — is decided by
// refineXXECallback, which inspects the raw callback request on the HTTP leg. A
// DNS-only hit carries no request to inspect and can be produced by any resolver
// in the path (the eventual HTTP fetch's own lookup, a crawler prefetch, a
// caching resolver), so it is rated Firm rather than Certain — one notch below
// the HTTP-fetch leg — matching how the SQLi/JWT out-of-band DNS legs are rated.
func classifyXXE(proto, injectionDesc string) (severity.Severity, severity.Confidence, string) {
	switch proto {
	case "http", "https":
		return severity.High, severity.Certain, "Blind XXE confirmed: the target's XML parser fetched the injected external entity/DTD over HTTP from the OAST server (" + injectionDesc + ")"
	case "dns":
		return severity.High, severity.Firm, "Blind XXE likely: the injected external-entity OAST subdomain was resolved over DNS (" + injectionDesc + "). The unguessable per-payload subdomain rules out coincidental resolution; DNS-only (no outbound fetch observed) keeps confidence at Firm — confirm via the HTTP-fetch leg or an in-band file:// read."
	default:
		return severity.High, severity.Firm, "Blind XXE likely via out-of-band " + proto + " interaction (" + injectionDesc + ")"
	}
}

// refineOASTCallback is the second-signal confirmation for out-of-band findings.
// A correlated hit on the unguessable per-payload subdomain proves the injected
// http://<oast> URL was reached — but NOT necessarily by the vulnerability firing.
// The systems that most often reach an injected URL are not the target's
// vulnerable code path at all:
//
//   - URL-preview / link-unfurling bots (Slack, Facebook, chat apps) that a
//     logged/echoed injected URL reaches.
//   - Site-monitoring & security crawlers (the reported wild FP: ginandjuice.shop's
//     own monitor fetching the injected URL with User-Agent "ginandjuice.shop;
//     support@portswigger.net" and an HTTP/2 cleartext upgrade).
//   - WAF / threat-intel enrichment pipelines that fetch URLs seen in traffic.
//
// These fetch the injected URL with a full browser/crawler HTTP client, so the
// callback carries fingerprints (a browser/bot User-Agent, an h2c upgrade, browser-
// only headers) that the vulnerability's real out-of-band fetcher never has. The
// refinement splits by how identifiable that real fetcher is:
//
//   - XXE, JWT jku/x5u, out-of-band SQLi, and command injection each have a SPECIFIC
//     non-browser fetcher — the XML parser, the JWKS/key fetcher, the database
//     engine, or curl/wget. None is ever a web browser or a crawler bot, so ANY
//     browser/crawler/h2c fingerprint on the HTTP leg is unambiguously a harvested-
//     URL fetch, not the vuln → Low / Tentative UNCONFIRMED (the aggressive
//     looksLikeHarvestedURLFetch check).
//   - Generic blind SSRF is different: its legitimate fetcher CAN be a headless
//     browser or an internal link-preview / unfurl service (both classic SSRF
//     sinks), so a browser UA or h2c handshake is not by itself a false positive.
//     It is downgraded only on the narrow signals no server-side fetcher ever
//     carries — a self-identifying contact address in the UA, or the UA naming the
//     target host (looksLikeExternalMonitor) — which preserves genuine headless-
//     browser SSRF.
//
// DNS callbacks (no request to fingerprint) and bare fetches consistent with the
// real fetcher are returned unchanged. This is the same downgrade idiom the
// command-injection classifier already uses for its protocol-mismatch / reflected-
// host guards.
func refineOASTCallback(interaction *server.Interaction, pctx PayloadContext, sev severity.Severity, conf severity.Confidence, desc string) (severity.Severity, severity.Confidence, string) {
	if interaction == nil {
		return sev, conf, desc
	}
	switch strings.ToLower(interaction.Protocol) {
	case "http", "https":
	default:
		// Only the HTTP leg carries a request whose client can be fingerprinted.
		return sev, conf, desc
	}
	raw, target := interaction.RawRequest, pctx.TargetURL

	// Classes with a specific, non-browser out-of-band fetcher → aggressive check.
	if label := harvestableFetchLabel(pctx.InjectionType); label != "" {
		if harvested, reason := looksLikeHarvestedURLFetch(raw, target); harvested {
			return severity.Low, severity.Tentative, "Possible " + label + ", UNCONFIRMED: an out-of-band HTTP request reached the OAST server for the injected out-of-band URL, but " + reason +
				". A crawler / URL-preview bot / site monitor / threat-intel pipeline that harvested the injected http://<oast> URL from request logs (or a feed) calls back identically without the vulnerability firing — this class's real out-of-band fetcher (XML parser / JWKS fetcher / database engine / curl-wget) is never a web browser or crawler. Confirm with an in-band signal, or a callback whose client is consistent with that fetcher (a library/tool User-Agent, no browser/h2c handshake), before treating this as confirmed."
		}
		return sev, conf, desc
	}

	// Generic blind SSRF → narrow check only (its fetcher may legitimately be a
	// headless browser / link-preview service). Skip anything already Info.
	if sev != severity.Info {
		if monitor, reason := looksLikeExternalMonitor(raw, target); monitor {
			return severity.Info, severity.Tentative, "Possible blind SSRF, UNCONFIRMED: an out-of-band HTTP request reached the OAST server, but " + reason +
				". An external site monitor / crawler that harvested the injected URL calls back identically without any server-side request forgery. Confirm the fetch originates from the target's own infrastructure before treating this as SSRF."
		}
	}
	return sev, conf, desc
}

// harvestableFetchLabel maps an OAST injection-type label to a human finding label
// when the class has a SPECIFIC non-browser out-of-band fetcher (so a browser/
// crawler callback is unambiguously a harvested-URL fetch, not the vuln). It
// mirrors the same substrings classifyInteraction dispatches on, so the two stay in
// lockstep. Returns "" for classes whose fetcher can legitimately be browser-like
// (generic SSRF), which refineOASTCallback handles with the narrower monitor check.
func harvestableFetchLabel(injectionType string) string {
	switch inj := strings.ToLower(injectionType); {
	case strings.Contains(inj, "xxe"):
		return "XXE"
	case strings.Contains(inj, "jwt"):
		return "JWT key-URL dereference"
	case strings.Contains(inj, "sql"):
		return "SQL injection"
	case strings.Contains(inj, "command"):
		return "OS command injection"
	default:
		return ""
	}
}

// browserUATokens are substrings that appear only in a browser / rendering-engine
// User-Agent — never in the client that dereferences an out-of-band URL for the
// classes handled by the aggressive check (an XML parser emits no UA / "Java/<ver>"
// / a library token; a JWKS fetcher, database engine, or curl/wget likewise carry a
// tool/library UA). Their presence on such a callback means a browser or headless
// renderer fetched the injected URL. Matched on a lowercased User-Agent value.
var browserUATokens = []string{
	"mozilla/", "applewebkit", "chrome/", "safari/", "gecko/", "firefox/",
	"edg/", "opr/", "msie ", "trident/", "headlesschrome",
}

// crawlerUATokens flag self-identifying crawlers, monitors, link/URL-preview bots,
// and out-of-band scanners — the systems that harvest an injected http://<oast>
// URL from request logs / threat-intel feeds and visit it independently of the
// vulnerable code path. curl/wget are deliberately NOT listed (curl/wget IS the
// command-injection fetcher, and a genuine server-side fetch may use them);
// "python-requests" is likewise omitted because a server's own JWKS/URL fetch can
// legitimately use the requests library. Matched on a lowercased User-Agent value.
var crawlerUATokens = []string{
	"bot", "crawler", "spider", "crawl", "slurp", "preview",
	"fetcher", "monitor", "scanner", "facebookexternalhit",
}

// uaContactRe matches an email/contact address embedded in a User-Agent — a
// self-identifying crawler / monitoring / abuse-contact convention (e.g.
// "ginandjuice.shop; support@portswigger.net") that a server-side out-of-band
// fetcher never advertises. Used by both the aggressive and the narrow checks.
var uaContactRe = regexp.MustCompile(`@[a-z0-9._%+-]+\.[a-z]{2,}`)

// looksLikeHarvestedURLFetch reports whether an out-of-band HTTP callback request
// was made by a crawler / URL-preview bot / security scanner / enrichment pipeline
// that harvested the injected OAST URL, rather than by the target's real out-of-band
// fetcher for a class whose fetcher is a specific non-browser client (XML parser,
// JWKS fetcher, database engine, curl/wget — see harvestableFetchLabel). It returns
// (true, reason) when a non-fetcher fingerprint is found — the reason is a lowercase
// clause for the finding description — and (false, "") for a bare fetch consistent
// with that fetcher or when there is no HTTP request to inspect. Deliberately
// conservative: it fires only on strong, fetcher-inconsistent signals so it never
// downgrades a genuine finding whose fetcher uses a minimal/library HTTP client.
func looksLikeHarvestedURLFetch(rawRequest, targetURL string) (bool, string) {
	if strings.TrimSpace(rawRequest) == "" {
		return false, ""
	}
	h := callbackHeaderMap(rawRequest)

	if ua := strings.ToLower(strings.TrimSpace(h["user-agent"])); ua != "" {
		for _, t := range browserUATokens {
			if strings.Contains(ua, t) {
				return true, "the callback came from a web browser / rendering engine (User-Agent \"" + ua + "\"), not a server-side out-of-band fetcher"
			}
		}
		for _, t := range crawlerUATokens {
			if strings.Contains(ua, t) {
				return true, "the callback identifies as a crawler / bot (User-Agent \"" + ua + "\"), not a server-side out-of-band fetcher"
			}
		}
		if uaContactRe.MatchString(ua) {
			return true, "the callback User-Agent advertises a contact address (\"" + ua + "\"), a self-identifying crawler / monitoring bot convention a server-side fetcher never uses"
		}
		if host := oastHost(targetURL); host != "" && strings.Contains(ua, host) {
			return true, "the callback User-Agent names the target host (\"" + ua + "\"), a site monitor / crawler, not a server-side out-of-band fetcher"
		}
	}

	// HTTP/2 cleartext upgrade negotiation is a full HTTP client / crawler behaviour
	// — a server-side out-of-band fetch is a plain request and never negotiates h2c.
	if strings.Contains(strings.ToLower(h["upgrade"]), "h2c") {
		return true, "the callback negotiated an HTTP/2 cleartext (h2c) upgrade, a full HTTP client / crawler behaviour a server-side out-of-band fetch never performs"
	}
	if _, ok := h["http2-settings"]; ok {
		return true, "the callback carried an HTTP2-Settings upgrade header, a full HTTP client / crawler behaviour a server-side out-of-band fetch never performs"
	}

	// Browser-only request headers. Require two so a lone header a proxy might add
	// (e.g. Accept-Language) cannot by itself downgrade a genuine callback.
	browserHdrs := 0
	for name := range h {
		if name == "accept-language" || name == "sec-ch-ua" || name == "upgrade-insecure-requests" ||
			name == "cookie" || name == "referer" || strings.HasPrefix(name, "sec-fetch-") {
			browserHdrs++
		}
	}
	if browserHdrs >= 2 {
		return true, "the callback carried browser-only request headers (Sec-Fetch-*/Accept-Language/Cookie/…) a server-side out-of-band fetch never sends"
	}

	return false, ""
}

// looksLikeExternalMonitor is the NARROW callback-source check for generic blind
// SSRF, whose legitimate fetcher can itself be a headless browser or an internal
// link-preview/unfurl service — so the aggressive browser/h2c fingerprints above
// would wrongly downgrade a genuine SSRF. It fires ONLY on the two signals no
// server-side fetcher ever carries: a self-identifying contact address in the
// User-Agent, or the User-Agent naming the target host (an external site monitor).
// Returns (true, reason) on a match, (false, "") otherwise or with no request.
func looksLikeExternalMonitor(rawRequest, targetURL string) (bool, string) {
	if strings.TrimSpace(rawRequest) == "" {
		return false, ""
	}
	ua := strings.ToLower(strings.TrimSpace(callbackHeaderMap(rawRequest)["user-agent"]))
	if ua == "" {
		return false, ""
	}
	if uaContactRe.MatchString(ua) {
		return true, "the callback User-Agent advertises a contact address (\"" + ua + "\"), a self-identifying external crawler / monitoring bot a server-side SSRF fetcher never uses"
	}
	if host := oastHost(targetURL); host != "" && strings.Contains(ua, host) {
		return true, "the callback User-Agent names the target host (\"" + ua + "\"), an external site monitor / crawler rather than the target's own fetcher"
	}
	return false, ""
}

// callbackHeaderMap parses the header lines of a raw HTTP callback request into a
// lowercased name → trimmed-value map. The request line (line 0) is skipped and
// parsing stops at the first blank line (end of headers), so a callback body can
// never be mistaken for a header. On a duplicated header the last value wins; that
// is sufficient for the presence/substring checks in looksLikeHarvestedURLFetch.
func callbackHeaderMap(rawRequest string) map[string]string {
	h := make(map[string]string)
	for i, line := range strings.Split(rawRequest, "\n") {
		if i == 0 {
			continue // request line
		}
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break // end of headers
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:idx]))
		h[name] = strings.TrimSpace(line[idx+1:])
	}
	return h
}

// classifySQLi rates out-of-band interactions triggered by an injected SQL
// out-of-band function. The per-payload subdomain is random and unguessable, so a
// correlated callback proves the database executed the injected function inside
// the query. An HTTP fetch (UTL_HTTP / COPY TO PROGRAM curl) is the strongest
// signal; a DNS-only hit (LOAD_FILE UNC / xp_dirtree / UTL_INADDR resolving the
// host) is one notch below but still rules out coincidence via the unique host.
func classifySQLi(proto, injectionDesc string) (severity.Severity, severity.Confidence, string) {
	switch proto {
	case "http", "https":
		return severity.Critical, severity.Certain, "Blind SQL injection confirmed: the database executed an injected out-of-band function that fetched the OAST server over HTTP (" + injectionDesc + ")"
	case "dns":
		return severity.High, severity.Firm, "Blind SQL injection likely: the database resolved a unique OAST subdomain via an injected out-of-band function (LOAD_FILE UNC / xp_dirtree / UTL_INADDR) (" + injectionDesc + "). The unguessable per-payload subdomain rules out coincidental resolution; DNS-only (no outbound fetch) keeps confidence at Firm."
	default:
		return severity.High, severity.Firm, "Blind SQL injection confirmed via out-of-band " + proto + " interaction (" + injectionDesc + ")"
	}
}

// classifyJWT rates out-of-band interactions triggered by a jku/x5u claim in a
// JWT header pointing at a unique OAST subdomain. A callback proves the server
// fetched the attacker-controlled key URL — one step from swapping in an attacker
// signing key (full authentication bypass), so it is reported High regardless of
// protocol (both DNS and HTTP legs mean the server resolved/fetched the URL).
func classifyJWT(proto, injectionDesc string) (severity.Severity, severity.Confidence, string) {
	switch proto {
	case "http", "https":
		return severity.High, severity.Certain, "JWT header key-URL injection confirmed: the server fetched the attacker-controlled jku/x5u URL from the token header over HTTP (" + injectionDesc + "). This enables signing-key injection / authentication bypass and is itself a server-side request forgery."
	case "dns":
		return severity.High, severity.Firm, "JWT header key-URL injection likely: the server resolved the attacker-controlled jku/x5u OAST subdomain from the token header via DNS (" + injectionDesc + "). The unguessable per-payload subdomain rules out coincidence; DNS-only (no fetch observed) keeps confidence at Firm."
	default:
		return severity.High, severity.Firm, "JWT header key-URL injection confirmed via out-of-band " + proto + " interaction (" + injectionDesc + ")"
	}
}

// infraResolvedClientHeaders is the client-IP / forwarding / proxy header family
// whose *values* edge infrastructure routinely resolves over DNS — for geo-IP,
// reverse-DNS, request logging, or WAF/threat-intel enrichment. A unique OAST
// hostname planted in any of these is therefore resolved passively, with no
// shell involvement, so a DNS-only command-injection callback on one of them is
// not proof of execution. (vigolium's own oast_probe module deliberately plants
// bare hosts into these same headers expecting exactly such DNS pingbacks — see
// pkg/modules/active/oast_probe.) Matched case-insensitively.
var infraResolvedClientHeaders = map[string]struct{}{
	"x-forwarded-for":     {},
	"x-real-ip":           {},
	"true-client-ip":      {},
	"cf-connecting-ip":    {},
	"x-client-ip":         {},
	"x-proxyuser-ip":      {},
	"forwarded":           {},
	"x-forwarded":         {},
	"x-originating-ip":    {},
	"x-remote-ip":         {},
	"x-remote-addr":       {},
	"client-ip":           {},
	"x-cluster-client-ip": {},
	"fastly-client-ip":    {},
}

// isInfraResolvedClientHeader reports whether name is a client-IP / forwarding
// header whose value edge infrastructure commonly resolves via DNS (see
// infraResolvedClientHeaders).
func isInfraResolvedClientHeader(name string) bool {
	if name == "" {
		return false
	}
	_, ok := infraResolvedClientHeaders[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// proxyReflectedHostHeaders is the host-injection header family whose *value* a
// reverse proxy / application routinely reflects into an outbound URL — an
// absolute redirect Location, an upstream-fetch target, a generated link — and
// then follows or fetches. A unique OAST hostname placed anywhere in one of these
// is therefore reached over HTTP (and resolved over DNS) by the infrastructure
// itself, with no shell involved: a bare "<header>: <oast-host>" carrying no shell
// metacharacter calls back identically (vigolium's own oast_probe plants exactly
// that and gets it classified as informational SSRF). So an OAST command-injection
// callback on one of these is the proxy reaching out, not proof a command ran —
// the dominant false-positive class for header-injected OAST command injection.
// Matched case-insensitively. Distinct from infraResolvedClientHeaders (client-IP
// headers resolved via DNS for geo-IP/logging — those rarely drive an HTTP fetch,
// so only their DNS callbacks are downgraded; these host-reflection headers drive
// both DNS and HTTP, so both are).
var proxyReflectedHostHeaders = map[string]struct{}{
	"x-forwarded-host":   {},
	"x-forwarded-server": {},
	"x-host":             {},
	"x-original-host":    {},
	"x-original-url":     {},
	"x-rewrite-url":      {},
}

// isProxyReflectedHostHeader reports whether name is a host-injection header whose
// value a proxy commonly reflects into an outbound redirect/upstream URL (see
// proxyReflectedHostHeaders).
func isProxyReflectedHostHeader(name string) bool {
	if name == "" {
		return false
	}
	_, ok := proxyReflectedHostHeaders[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// cmdiPayloadExpectsHTTP inspects a recorded command-injection payload and reports
// which out-of-band protocol *executing the command* could produce: a DNS-lookup
// command (nslookup/ping) can only generate a DNS callback, whereas a fetch command
// (curl/wget) makes an outbound HTTP request. expectsHTTP is true only for the
// fetch commands. known is false when the payload was not recorded or carries no
// recognised OAST command, so the caller must not draw a protocol-mismatch
// conclusion from it. Matching is on the tool name followed by a space (the command
// always has an argument, and a hostname never contains a space), so a host that
// merely embeds "ping"/"curl" as a substring is never mistaken for the command.
//
// The recognised tools mirror the command set planted by the OAST cmdi shapes in
// pkg/modules/infra/cmdinj.go (CmdiOASTShapes / CmdiOASTHeaderShapes): nslookup,
// ping, curl, wget. If a new fetch- or DNS-tool shape is added there, add its tool
// name here too — otherwise this returns known=false for it and the
// protocol-mismatch guard silently skips that payload. (The mapping is re-derived
// from the rendered string rather than carried on the shape to keep this package
// free of an import of pkg/modules/infra.)
func cmdiPayloadExpectsHTTP(payload string) (known, expectsHTTP bool) {
	if payload == "" {
		return false, false
	}
	p := strings.ToLower(payload)
	switch {
	case strings.Contains(p, "curl ") || strings.Contains(p, "wget "):
		return true, true
	case strings.Contains(p, "nslookup ") || strings.Contains(p, "ping "):
		return true, false
	default:
		return false, false
	}
}

// classifyCommandInjection rates out-of-band interactions triggered by an
// injected OS command. The per-payload subdomain is random and unguessable, so a
// callback proves the unique hostname was reached — but *how* it was reached
// determines whether a shell actually ran. Two false-positive guards apply before
// an HTTP callback is trusted as command execution:
//
//   - Protocol-expectation mismatch. The injected command fixes which OAST
//     protocol executing it can produce: nslookup/ping do a DNS lookup only;
//     curl/wget make an HTTP request. A DNS-only command cannot make an outbound
//     HTTP request by running, so an HTTP(S) callback for such a payload means the
//     unique OAST host was reached as a URL substring — a proxy reflecting a
//     forwarding/host header into a redirect Location or upstream request and
//     fetching it — not a shell. This is the exact wild false positive on
//     X-Forwarded-Host: a ";nslookup <oast>" payload yielding an HTTPS GET (with a
//     browser User-Agent, no less). → Low / Tentative, UNCONFIRMED.
//   - Proxy-reflected host header. Even a fetch command (;curl http://<oast>)
//     injected into X-Forwarded-Host & family is suspect, because the proxy fetches
//     a host/URL embedded in these headers regardless of any shell metacharacter —
//     a bare "<header>: <oast-host>" control calls back identically. → Low /
//     Tentative, UNCONFIRMED (the SSRF/host-injection angle is captured separately
//     by oast_probe).
//
// Otherwise:
//   - HTTP/HTTPS callback for a fetch command on a genuine parameter / non-reflected
//     header: a passive middlebox resolves DNS but does not fetch the planted URL,
//     so an outbound HTTP request means the command executed → Critical / Certain.
//   - DNS-only callback on a client-IP / forwarding header or a proxy-reflected host
//     header: NOT proof of execution (edge infra resolves client-IP headers for
//     geo-IP/logging; proxies resolve reflected host headers for routing) → Low /
//     Tentative, surfaced as an unconfirmed lead.
//   - DNS-only callback on a genuine request parameter (or a non-forwarding header):
//     a unique unguessable subdomain resolving for an injected command is a strong
//     lead, but DNS-only (no outbound fetch) is one notch below HTTP-fetch proof →
//     High / Firm.
func classifyCommandInjection(proto string, pctx PayloadContext, injectionDesc string) (severity.Severity, severity.Confidence, string) {
	reflectedHostHeader := isProxyReflectedHostHeader(pctx.ParameterName)

	switch proto {
	case "http", "https":
		// Guard 1: a DNS-only command (nslookup/ping) cannot produce an HTTP
		// callback by executing — the OAST host was reached as a URL substring by
		// the infrastructure, not by a shell.
		if known, expectsHTTP := cmdiPayloadExpectsHTTP(pctx.Payload); known && !expectsHTTP {
			return severity.Low, severity.Tentative, "Possible OS command injection, UNCONFIRMED: an out-of-band HTTP request reached the OAST server, but the injected command was DNS-only (nslookup/ping) and cannot itself make an HTTP request (" + injectionDesc +
				"). The unique OAST host was almost certainly reached as a URL substring — a proxy reflecting a forwarding/host header value into a redirect Location or upstream request and fetching it — not by a shell; a bare-host control (no ';' metacharacter) in the same position would call back identically. Confirm with a curl/wget payload whose HTTP callback carries a curl/wget User-Agent before treating this as command injection."
		}
		// Guard 2: even a fetch command injected into a proxy-reflected host header
		// is suspect — the proxy fetches the host/URL embedded in the header value
		// whether or not the shell metacharacter is present.
		if reflectedHostHeader {
			return severity.Low, severity.Tentative, "Possible OS command injection, UNCONFIRMED: an out-of-band HTTP request reached the OAST server for a payload injected into the host-reflection header " + pctx.ParameterName + " (" + injectionDesc +
				"). Reverse proxies routinely reflect this header's value into an outbound redirect Location or upstream request URL, so the OAST host is fetched whether or not a shell metacharacter is present — a bare \"" + pctx.ParameterName + ": <oast-host>\" control calls back identically (see the oast_probe module). Treat this as blind SSRF / host-header injection unless a curl/wget User-Agent on the callback confirms a shell ran."
		}
		return severity.Critical, severity.Certain, "Blind OS command injection confirmed: target executed an injected fetch command (curl/wget) calling the OAST server over HTTP (" + injectionDesc + ")"
	case "dns":
		if isInfraResolvedClientHeader(pctx.ParameterName) {
			return severity.Low, severity.Tentative, "Possible OS command injection, UNCONFIRMED: a unique OAST subdomain injected into the client-IP/forwarding header " + pctx.ParameterName +
				" was resolved over DNS (" + injectionDesc + "). Edge infrastructure (geo-IP, reverse-DNS, logging, WAF) routinely resolves the value of these headers, so a DNS-only callback is NOT proof a shell ran. Confirm via an HTTP-fetch callback (curl/wget) before treating this as command injection."
		}
		if reflectedHostHeader {
			return severity.Low, severity.Tentative, "Possible OS command injection, UNCONFIRMED: a unique OAST subdomain injected into the host-reflection header " + pctx.ParameterName +
				" was resolved over DNS (" + injectionDesc + "). Reverse proxies resolve the host in these headers for routing, so a DNS-only callback is NOT proof a shell ran. Confirm via an HTTP-fetch callback (curl/wget) before treating this as command injection."
		}
		return severity.High, severity.Firm, "Blind OS command injection likely: target resolved a unique OAST subdomain via DNS for an injected command (nslookup/host/ping) (" + injectionDesc + "). The unguessable per-payload subdomain rules out coincidental resolution; DNS-only (no outbound HTTP fetch) keeps confidence at Firm rather than Certain."
	default:
		return severity.High, severity.Firm, "Blind OS command injection confirmed via out-of-band " + proto + " interaction (" + injectionDesc + ")"
	}
}

// extractNonce extracts the subdomain part (correlationID+nonce) from an OAST URL.
// Input: "correlationIDnonce.server.host" → Output: "correlationIDnonce"
func extractNonce(url string) string {
	dot := strings.IndexByte(url, '.')
	if dot <= 0 {
		return ""
	}
	return url[:dot]
}
