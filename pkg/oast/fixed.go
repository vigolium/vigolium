package oast

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/rs/xid"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// Fixed-URL correlation.
//
// oast.oast_url (or --oast-url) replaces interactsh with a callback endpoint the
// operator runs. A plain URL is handed to every probe as it is, so a callback
// cannot say which probe caused it ("fixed-uncorrelated"). A URL carrying the
// {nonce} placeholder ("https://{nonce}.cb.example.com" or
// "https://cb.example.com/{nonce}") gets a locally minted nonce per probe: the
// nonce → PayloadContext mapping is kept in the in-memory tracker and persisted
// to oast_payloads, so `vigolium oast ingest` can attribute the callbacks the
// operator's endpoint logged, after the scan is gone.

// NoncePlaceholder is the token in oast_url replaced by a per-probe nonce.
const NoncePlaceholder = "{nonce}"

// OAST modes, as reported by Service.Mode.
const (
	// ModeInteractsh: callback hosts come from a registered interactsh session.
	ModeInteractsh = "interactsh"
	// ModeFixedTemplate: oast_url carries {nonce}; every probe gets its own
	// nonce and callbacks are attributed with `vigolium oast ingest`.
	ModeFixedTemplate = "fixed-template"
	// ModeFixedUncorrelated: oast_url has no {nonce}; every probe plants the
	// same URL, so a callback cannot be attributed to a probe.
	ModeFixedUncorrelated = "fixed-uncorrelated"
)

// oastPayloadFlushBatch is how many minted payload contexts are buffered before
// they are written to oast_payloads in one insert. Flush and Close write the
// remainder.
const oastPayloadFlushBatch = 256

// fixedTemplate is a parsed {nonce} oast_url, scheme stripped: a minted
// callback is prefix + nonce + suffix, the same bare host[/path] shape the
// interactsh client hands out, so modules that write "http://"+url or
// "nslookup "+url keep working.
type fixedTemplate struct {
	prefix, suffix string
}

// parseFixedTemplate parses an oast_url carrying exactly one {nonce}. It
// returns nil for a URL without the placeholder (or with more than one, which
// cannot be rendered unambiguously).
func parseFixedTemplate(raw string) *fixedTemplate {
	raw = strings.TrimSpace(raw)
	if strings.Count(raw, NoncePlaceholder) != 1 {
		return nil
	}
	if i := strings.Index(raw, "://"); i >= 0 && i < strings.Index(raw, NoncePlaceholder) {
		raw = raw[i+len("://"):]
	}
	prefix, suffix, _ := strings.Cut(raw, NoncePlaceholder)
	return &fixedTemplate{prefix: prefix, suffix: suffix}
}

// render returns the callback URL for nonce.
func (t *fixedTemplate) render(nonce string) string {
	return t.prefix + nonce + t.suffix
}

// nonceOf recovers the nonce from a callback URL render produced. A scheme the
// caller may have added is ignored.
func (t *fixedTemplate) nonceOf(callbackURL string) string {
	u := callbackURL
	if i := strings.Index(u, "://"); i >= 0 && !strings.Contains(t.prefix, "://") {
		u = u[i+len("://"):]
	}
	if !strings.HasPrefix(u, t.prefix) || !strings.HasSuffix(u, t.suffix) || len(u) < len(t.prefix)+len(t.suffix) {
		return ""
	}
	return u[len(t.prefix) : len(u)-len(t.suffix)]
}

// mintNonce returns a new nonce: an xid (20 chars of [0-9a-v]), unique without
// coordination and safe as a DNS label or a path segment.
func mintNonce() string {
	return xid.New().String()
}

// Mode reports how callback URLs are produced: ModeInteractsh,
// ModeFixedTemplate or ModeFixedUncorrelated. "" for a nil Service.
func (s *Service) Mode() string {
	switch {
	case s == nil:
		return ""
	case s.fixedURL == "":
		return ModeInteractsh
	case s.template != nil:
		return ModeFixedTemplate
	default:
		return ModeFixedUncorrelated
	}
}

// mintFixed mints a nonce, renders the callback URL from the template, tracks
// the payload context and queues it for oast_payloads.
func (s *Service) mintFixed(pctx PayloadContext) string {
	nonce := mintNonce()
	pctx.CallbackURL = s.template.render(nonce)
	s.trackerCache().Add(nonce, pctx)
	s.queuePayload(&database.OASTPayload{
		Nonce:       nonce,
		ProjectUUID: s.projectUUID,
		ScanUUID:    s.scanUUID,
		Class:       string(pctx.class()),
		ModuleID:    pctx.ModuleID,
		TargetURL:   pctx.TargetURL,
		Param:       pctx.ParameterName,
		RequestHash: pctx.RequestHash,
	})
	return pctx.CallbackURL
}

// recordFixedPayload is RecordPayload for a {nonce} template: it updates the
// tracker and the persisted row (still queued, or already written).
func (s *Service) recordFixedPayload(callbackURL, payload string) {
	nonce := s.template.nonceOf(callbackURL)
	if nonce == "" {
		return
	}
	cache := s.trackerCache()
	if pctx, ok := cache.Get(nonce); ok {
		pctx.Payload = payload
		cache.Add(nonce, pctx)
	}
	s.recordStoredPayload(nonce, payload)
}

// queuePayload buffers one payload context and writes the buffer once it holds
// oastPayloadFlushBatch rows.
func (s *Service) queuePayload(p *database.OASTPayload) {
	if s.repo == nil {
		return
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	if s.pendingPayloads == nil {
		s.pendingPayloads = make(map[string]*database.OASTPayload)
	}
	s.pendingPayloads[p.Nonce] = p
	s.maybeWritePendingLocked()
}

// maybeWritePendingLocked writes the buffer once it holds
// oastPayloadFlushBatch entries; payloadMu must be held.
func (s *Service) maybeWritePendingLocked() {
	if len(s.pendingPayloads)+len(s.pendingValues) >= oastPayloadFlushBatch {
		s.writePendingLocked()
	}
}

// flushPayloads writes every buffered payload context. Called from Flush and
// Close; safe on a nil Service.
func (s *Service) flushPayloads() {
	if s == nil || s.repo == nil {
		return
	}
	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()
	s.writePendingLocked()
}

// writePendingLocked writes the buffer: queued rows first, then planted
// values for rows written earlier. payloadMu must be held, which also keeps a
// concurrent RecordPayload from updating a row whose insert is in flight.
func (s *Service) writePendingLocked() {
	if len(s.pendingPayloads) > 0 {
		rows := slices.Collect(maps.Values(s.pendingPayloads))
		s.pendingPayloads = nil
		if err := s.repo.SaveOASTPayloads(context.Background(), rows); err != nil {
			zap.L().Warn("OAST: failed to persist payload contexts; their callbacks cannot be ingested later",
				zap.Int("payloads", len(rows)), zap.Error(err))
		}
	}
	if len(s.pendingValues) > 0 {
		values := s.pendingValues
		s.pendingValues = nil
		if err := s.repo.SetOASTPayloadValues(context.Background(), values); err != nil {
			zap.L().Warn("OAST: failed to record planted payloads", zap.Int("payloads", len(values)), zap.Error(err))
		}
	}
}
