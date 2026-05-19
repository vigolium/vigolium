package oast

import (
	"context"
	"strings"
	"sync"
	"time"

	interactshclient "github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
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
}

// Service wraps an interactsh client with payload tracking and result emission.
type Service struct {
	client             *interactshclient.Client
	tracker            sync.Map // nonce → PayloadContext
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
		s.tracker.Store(nonce, PayloadContext{
			TargetURL:     targetURL,
			ParameterName: paramName,
			InjectionType: injectionType,
			ModuleID:      moduleID,
			RequestHash:   requestHash,
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
	val, found := s.tracker.Load(nonce)

	var pctx PayloadContext
	if found {
		pctx = val.(PayloadContext)
	}

	zap.L().Info("OAST: interaction received",
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

	// Save finding to database, linked to the originating HTTP record
	s.saveFinding(result, pctx.RequestHash)

	if s.emitResult != nil {
		s.emitResult(result)
	}
}

// saveFinding persists a Finding to the database, linked to the HTTP record
// that originated the OAST payload (resolved via requestHash).
func (s *Service) saveFinding(result *output.ResultEvent, requestHash string) {
	if s.repo == nil || requestHash == "" {
		return
	}

	// Resolve the request hash to a database record UUID
	var recordUUIDs []string
	if s.resolveRequestUUID != nil {
		if uuid := s.resolveRequestUUID(requestHash); uuid != "" {
			recordUUIDs = append(recordUUIDs, uuid)
		}
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

	switch proto {
	case "http", "https":
		return severity.High, "Blind SSRF confirmed: target made outbound HTTP request to OAST server (" + injectionDesc + ")"
	case "dns":
		return severity.Info, "DNS interaction detected: target resolved OAST domain (" + injectionDesc + "). May indicate blind SSRF/XXE but DNS alone is lower confidence."
	default:
		return severity.Medium, "Out-of-band " + protocol + " interaction detected (" + injectionDesc + ")"
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
