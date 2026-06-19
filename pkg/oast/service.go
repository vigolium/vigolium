package oast

import (
	"context"
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

	zap.L().Info("OAST: interaction received",
		zap.String("protocol", interaction.Protocol),
		zap.String("unique_id", interaction.UniqueID),
		zap.String("remote_addr", interaction.RemoteAddress),
		zap.Bool("correlated", found))

	// Recover the request that planted the payload so both the persisted
	// interaction and the finding can be traced back to it without a manual join.
	originUUID, origin := s.originRecord(pctx.RequestHash)

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

	sev, desc := classifyInteraction(interaction.Protocol, pctx)
	result := &output.ResultEvent{
		ModuleID: pctx.ModuleID,
		URL:      pctx.TargetURL,
		Matched:  pctx.TargetURL,
		Info: output.Info{
			Name:        "Out-of-Band Interaction Detected",
			Description: desc,
			Severity:    sev,
			Confidence:  severity.Certain,
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
	}

	// Attach the originating request and human-readable trace anchors so the
	// finding answers "which request caused this callback?" on its own.
	enrichOASTResult(result, interaction, pctx, origin)

	// Save finding to database, linked to the originating HTTP record
	s.saveFinding(result, originUUID)

	if s.emitResult != nil {
		s.emitResult(result)
	}
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
		if out, err := httpmsg.AddOrReplaceHeader(raw, pctx.ParameterName, "http://"+host); err == nil {
			return string(out)
		}
	}
	return string(raw)
}

// describeInjectedPayload renders a one-line "<payload> (<where>)" summary of the
// planted OAST payload for the injected_payload anchor.
func describeInjectedPayload(pctx PayloadContext, proto string) string {
	host := callbackHost(pctx.CallbackURL)
	switch {
	case strings.EqualFold(pctx.ParameterName, "request-line"):
		return callbackScheme(proto) + "://" + host + "/ (request-line)"
	case isHeaderInjection(pctx):
		return "http://" + host + " (header " + pctx.ParameterName + ")"
	case pctx.ParameterName != "":
		return host + " (parameter " + pctx.ParameterName + ")"
	default:
		return host
	}
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

// classifyInteraction determines severity and description based on protocol.
func classifyInteraction(protocol string, pctx PayloadContext) (severity.Severity, string) {
	proto := strings.ToLower(protocol)

	injectionDesc := pctx.InjectionType
	if pctx.ParameterName != "" {
		injectionDesc += " via parameter " + pctx.ParameterName
	}

	// Command-injection OAST payloads (nslookup/ping/curl/wget of a unique,
	// unguessable subdomain) carry a different meaning than the generic
	// SSRF/XXE interpretation: a callback means a shell command actually ran, so
	// even a DNS-only interaction is high-confidence command execution.
	if strings.Contains(strings.ToLower(pctx.InjectionType), "command") {
		return classifyCommandInjection(proto, injectionDesc)
	}

	// XXE payloads (an external DTD / external entity pointing at a unique,
	// unguessable OAST subdomain) mean the target's XML parser resolved the
	// injected reference — unforgeable proof the parser loads external entities.
	// A DNS-only hit is high-confidence here (unlike the generic SSRF case)
	// because the per-payload subdomain rules out coincidental resolution.
	if strings.Contains(strings.ToLower(pctx.InjectionType), "xxe") {
		return classifyXXE(proto, injectionDesc)
	}

	// Host-routing SSRF — request-line manipulation (routing-ssrf) and
	// X-Forwarded-Host header injection — is frequently low-impact: the proxy's
	// outbound fetch often reaches nothing exploitable. Its OAST callbacks are
	// reported as informational rather than high. Scoped narrowly: genuine
	// parameter-based blind SSRF and the other forwarding-header injections
	// (X-Forwarded-For, Referer, Origin, …) stay high. The routing_ssrf module ID
	// is matched as a string literal to avoid an import cycle (it imports this
	// package); the header name is matched case-insensitively.
	hostRoutingSSRF := pctx.ModuleID == "routing-ssrf" || strings.EqualFold(pctx.ParameterName, "X-Forwarded-Host")
	if hostRoutingSSRF && (proto == "http" || proto == "https") {
		return severity.Info, "Blind SSRF confirmed: target made outbound HTTP request to OAST server (" + injectionDesc + ")"
	}

	switch proto {
	case "http", "https":
		return severity.High, "Blind SSRF confirmed: target made outbound HTTP request to OAST server (" + injectionDesc + ")"
	case "dns":
		return severity.Info, "DNS interaction detected: target resolved OAST domain (" + injectionDesc + "). May indicate blind SSRF/XXE but DNS alone is lower confidence."
	default:
		return severity.Medium, "Out-of-band " + protocol + " interaction detected (" + injectionDesc + ")"
	}
}

// classifyXXE rates out-of-band interactions triggered by an injected external
// DTD/entity. The per-payload subdomain is random and unguessable, so a
// correlated callback is proof the XML parser resolved the external reference.
func classifyXXE(proto, injectionDesc string) (severity.Severity, string) {
	switch proto {
	case "http", "https":
		return severity.High, "Blind XXE confirmed: the target's XML parser fetched the injected external entity/DTD over HTTP from the OAST server (" + injectionDesc + ")"
	case "dns":
		return severity.High, "Blind XXE confirmed: the target's XML parser resolved the injected external-entity OAST subdomain (DNS) (" + injectionDesc + "). The unguessable per-payload subdomain rules out coincidental resolution."
	default:
		return severity.High, "Blind XXE confirmed via out-of-band " + proto + " interaction (" + injectionDesc + ")"
	}
}

// classifyCommandInjection rates out-of-band interactions triggered by an
// injected OS command. The per-payload subdomain is random and unguessable, so a
// correlated callback is unforgeable proof that the injected command executed.
func classifyCommandInjection(proto, injectionDesc string) (severity.Severity, string) {
	switch proto {
	case "http", "https":
		return severity.Critical, "Blind OS command injection confirmed: target executed an injected fetch command (curl/wget) calling the OAST server over HTTP (" + injectionDesc + ")"
	case "dns":
		return severity.High, "Blind OS command injection confirmed: target executed an injected DNS-resolving command (nslookup/host/ping) for a unique OAST subdomain (" + injectionDesc + "). The unguessable per-payload subdomain rules out coincidental resolution."
	default:
		return severity.High, "Blind OS command injection confirmed via out-of-band " + proto + " interaction (" + injectionDesc + ")"
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
