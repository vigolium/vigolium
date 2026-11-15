package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/vigolium/vigolium/internal/config"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/burpscope"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"github.com/vigolium/vigolium/pkg/input/formats/urls"
	"github.com/vigolium/vigolium/pkg/input/formats/wsdl"
	"github.com/vigolium/vigolium/pkg/input/source"
	"go.uber.org/zap"
)

// isIngestInScope checks whether a request/response pair should be saved into
// projectUUID: the project's scope (the server's, with its config overlay),
// static files always filtered, full rules only when applied_on_ingest is set.
// A project overlay that cannot be read refuses the record (logged) rather
// than judging it by the wider global scope.
func (h *Handlers) isIngestInScope(rr *httpmsg.HttpRequestResponse, projectUUID string) bool {
	return h.ingestAdmitter(projectUUID)(rr)
}

// ingestAdmitter resolves projectUUID's ingest scope once and returns its
// admit rule, so a batch ingest judges every record without re-resolving the
// scope per record. When the scope cannot be resolved the error is logged
// once and every record is refused.
func (h *Handlers) ingestAdmitter(projectUUID string) func(*httpmsg.HttpRequestResponse) bool {
	scope, err := h.ingestScopeFor(projectUUID)
	if err != nil {
		zap.L().Warn("Ingest: project scope unavailable; records not stored",
			zap.String("project_uuid", projectUUID), zap.Error(err))
		return func(*httpmsg.HttpRequestResponse) bool { return false }
	}
	return scope.admit
}

// fetchResponseIfNeeded fetches the HTTP response for a request if one isn't
// already attached and fetching is not disabled. On failure it returns the
// original request-only record so ingestion can proceed.
func (h *Handlers) fetchResponseIfNeeded(rr *httpmsg.HttpRequestResponse) *httpmsg.HttpRequestResponse {
	if rr.HasResponse() {
		return rr
	}
	if h.config.DisableFetchResponse || h.httpRequester == nil {
		return rr
	}

	respChain, elapsed, err := h.httpRequester.Execute(rr, http.Options{})
	if err != nil {
		zap.L().Debug("Failed to fetch response during ingestion",
			zap.String("url", rr.Target()), zap.Error(err))
		return rr
	}

	fullResp := respChain.FullResponseBytes()
	raw := make([]byte, len(fullResp))
	copy(raw, fullResp)
	respChain.Close()

	// This record is persisted, and this send is the only chance to record its
	// timing — the converter cannot recover it from the bytes.
	return rr.WithResponse(httpmsg.NewHttpResponseWithDuration(raw, elapsed))
}

// IngestSourceHeader lets a client declare which tool the traffic it is pushing
// came from, so a record ingested by the Caido plugin is distinguishable from
// one pushed by curl. Mirrors the X-Project-UUID convention: a header rather
// than a body field, because the seven ingest modes share three save helpers
// but seven request shapes.
const IngestSourceHeader = "X-Vigolium-Source"

// ingestSource resolves the source label for an ingestion request: the client's
// declared tool when it names an allowed one, otherwise the generic
// ingest-server label this endpoint has always written.
//
// The allowlist is database.IsBridgeRecordSource rather than a local table, and
// it is an allowlist and not a passthrough on purpose: http_records.source is
// not only a display label, it decides which rows scan-on-receive feeds back
// into a running scan (database.IngestRecordSources) and which rows the executor
// treats as its own artefacts. A client free to send source="scanner" could
// silently exclude its own traffic from the scan it just asked for.
func ingestSource(c fiber.Ctx) string {
	declared := strings.ToLower(strings.TrimSpace(c.Get(IngestSourceHeader)))
	if declared == "" {
		return database.RecordSourceIngestServer
	}
	if database.IsBridgeRecordSource(declared) {
		return declared
	}
	zap.L().Debug("ignoring unrecognised ingest source header",
		zap.String("header", IngestSourceHeader), zap.String("declared", declared))
	return database.RecordSourceIngestServer
}

// saveRecord persists an HTTP record, routing through the RecordWriter when
// available (batched writes) or falling back to a direct repository insert.
func (h *Handlers) saveRecord(ctx context.Context, rr *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	if h.recordWriter != nil {
		return h.recordWriter.Write(ctx, rr, source, projectUUID)
	}
	return h.repo.SaveRecord(ctx, rr, source, projectUUID)
}

// ingestBatchChunk bounds how many records a bulk importer accumulates before a
// batched flush, so memory stays bounded while a single producer still fills real
// writer batches instead of paying one flush interval per record.
const ingestBatchChunk = 256

// saveRecordBatch persists a slice of records in one batched operation. Unlike a
// Write-in-a-loop (each Write blocks until its own record is flushed, so a lone
// bulk importer never fills a batch), the RecordWriter's SaveRecordBatch enqueues
// everything before awaiting, so the records coalesce into real transactions.
// Returns the number persisted (new + deduplicated) and any errors encountered.
func (h *Handlers) saveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source, projectUUID string) (int, []string) {
	if len(records) == 0 {
		return 0, nil
	}
	var uuids []string
	var err error
	if h.recordWriter != nil {
		uuids, err = h.recordWriter.SaveRecordBatch(ctx, records, source, projectUUID)
	} else {
		uuids, err = h.repo.SaveRecordBatch(ctx, records, source, projectUUID)
	}
	saved := database.CountSaved(uuids)
	var errs []string
	if err != nil {
		errs = append(errs, err.Error())
	}
	return saved, errs
}

// ingestAccumulator batches in-scope records from a bulk importer's parser
// callback, flushing in bounded chunks so memory stays bounded while records
// still coalesce into real writer batches (instead of one blocking flush per
// record). Not safe for concurrent use — parser callbacks run sequentially.
type ingestAccumulator struct {
	h           *Handlers
	ctx         context.Context
	source      string
	projectUUID string
	batch       []*httpmsg.HttpRequestResponse
	imported    int
	errors      []string

	// derive, when set, scopes a multi-host capture to its primary host:
	// the first record's host. Records for other hosts are stored
	// as context (RecordSourceIngestContext) — kept, never fetched, never
	// scanned by scan-on-receive.
	derive       *derivedIngestScope
	contextBatch []*httpmsg.HttpRequestResponse
	contextOnly  int
}

// derivedIngestScope is the scope a REST file ingest derives from its first
// record when the project names no targets.
type derivedIngestScope struct {
	cfg     config.ScopeConfig
	primary string
	matcher *config.ScopeMatcher
}

// deriveScope turns on primary-host scoping for this accumulator, unless the
// project's scope origin is "all" (the operator asked for every host).
func (a *ingestAccumulator) deriveScope() *ingestAccumulator {
	if a.source != database.RecordSourceIngestServer {
		return a // bridge pushes (Burp, Caido) are deliberate per record
	}
	settings, err := a.h.settingsForProject(a.projectUUID)
	if err != nil || settings == nil {
		return a
	}
	if config.ResolveCLIOriginMode(settings.Scope.CLIOriginMode) == "all" {
		return a
	}
	a.derive = &derivedIngestScope{cfg: settings.Scope}
	return a
}

// inDerivedScope reports whether rr belongs to the capture's derived scope
// (always true without derivation). The first record fixes the primary host.
func (a *ingestAccumulator) inDerivedScope(rr *httpmsg.HttpRequestResponse) bool {
	if a.derive == nil || rr == nil || rr.Service() == nil {
		return true
	}
	host := strings.ToLower(rr.Service().Host())
	if host == "" {
		return true
	}
	if a.derive.matcher == nil {
		a.derive.primary = host
		a.derive.matcher = config.NewScopeMatcher(a.derive.cfg, host)
	}
	return a.derive.matcher.HostInScope(host)
}

// derivedPrimary is the derived scope's primary host ("" without one).
func (a *ingestAccumulator) derivedPrimary() string {
	if a.derive == nil {
		return ""
	}
	return a.derive.primary
}

func (h *Handlers) newIngestAccumulator(ctx context.Context, source, projectUUID string) *ingestAccumulator {
	return &ingestAccumulator{
		h:           h,
		ctx:         ctx,
		source:      source,
		projectUUID: projectUUID,
		batch:       make([]*httpmsg.HttpRequestResponse, 0, ingestBatchChunk),
	}
}

// add queues a record, flushing automatically when a chunk fills.
func (a *ingestAccumulator) add(rr *httpmsg.HttpRequestResponse) {
	if !a.inDerivedScope(rr) {
		a.contextOnly++
		a.contextBatch = append(a.contextBatch, rr)
		if len(a.contextBatch) >= ingestBatchChunk {
			a.flushContext()
		}
		return
	}
	a.batch = append(a.batch, rr)
	if len(a.batch) >= ingestBatchChunk {
		a.flush()
	}
}

// flushContext persists queued out-of-derived-scope records as context.
func (a *ingestAccumulator) flushContext() {
	if len(a.contextBatch) == 0 {
		return
	}
	n, errs := a.h.saveRecordBatch(a.ctx, a.contextBatch, database.RecordSourceIngestContext, a.projectUUID)
	a.imported += n
	a.errors = append(a.errors, errs...)
	a.contextBatch = a.contextBatch[:0]
}

// flush persists the currently-queued records.
func (a *ingestAccumulator) flush() {
	if len(a.batch) == 0 {
		return
	}
	n, errs := a.h.saveRecordBatch(a.ctx, a.batch, a.source, a.projectUUID)
	a.imported += n
	a.errors = append(a.errors, errs...)
	a.batch = a.batch[:0]
}

// finish drains the final partial chunk and returns the totals. Callers use this
// once parsing completes instead of calling flush + reading the fields directly.
func (a *ingestAccumulator) finish() (imported int, errs []string) {
	a.flush()
	a.flushContext()
	return a.imported, a.errors
}

// HandleIngestHTTP handles POST /api/ingest-http
func (h *Handlers) HandleIngestHTTP(c fiber.Ctx) error {
	if h.repo == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	var req IngestHTTPRequest
	if err := c.Bind().JSON(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
	}

	if req.InputMode == "" {
		return respondError(c, fiber.StatusBadRequest, ErrMissingMode)
	}

	// Detached on purpose: ingestion persists records, and when the async
	// RecordWriter is enabled it enqueues the write then flushes on a background
	// context — the record lands regardless of the client. Binding the request
	// context here would let a client disconnect (between enqueue and flush)
	// return an error for a record that was in fact saved. Persistence must be
	// durable, so we use a background context.
	ctx := context.Background()

	// Three REST-only single-item modes have no file equivalent. Everything
	// else is an input-format name from the same registry -I uses (legacy REST
	// names such as postman_collection/http_archive/url_file are aliases there),
	// or "auto" to detect it from the content.
	mode := strings.ToLower(strings.TrimSpace(req.InputMode))
	switch mode {
	case "burp_base64":
		return h.ingestBurpBase64(c, ctx, &req)
	case "curl":
		return h.ingestCurl(c, ctx, &req)
	case "url":
		return h.ingestURL(c, ctx, &req)
	}

	content, err := resolveContent(&req)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, err)
	}

	var format, detected string
	if mode == ingestModeAuto {
		det := source.DetectFormatHead(headOf(content), "")
		if det.Format == "" {
			return respondErrorMsg(c, fiber.StatusBadRequest, "input_unparsed: could not detect the input format from the content; set input_mode explicitly", "supported input_mode values: "+strings.Join(supportedIngestModes(), ", "))
		}
		format, detected = det.Format, det.Format
		zap.L().Info("ingest: detected input format",
			zap.String("format", det.Format), zap.String("reason", det.Reason))
	} else {
		info, ok := source.LookupFormat(mode)
		if !ok || mode == "" {
			return respondErrorMsg(c, fiber.StatusBadRequest, fmt.Sprintf("unsupported_input_mode: %q is not a supported input_mode", req.InputMode), "supported input_mode values: "+strings.Join(supportedIngestModes(), ", "))
		}
		format = info.Name
	}

	switch format {
	case "urls":
		return h.ingestURLFile(c, ctx, &req, content, detected)
	case "openapi":
		return h.ingestOpenAPI(c, ctx, &req, content, detected)
	default:
		return h.ingestFileFormat(c, ctx, &req, content, format, detected)
	}
}

// ingestModeAuto is the input_mode that detects the format from the content.
const ingestModeAuto = "auto"

// supportedIngestModes lists every accepted input_mode: the REST-only
// single-item modes, "auto", then each registry format with its aliases.
func supportedIngestModes() []string {
	modes := []string{"url", "burp_base64", "curl", ingestModeAuto}
	for _, f := range source.Formats() {
		if f.Name == "curl" {
			continue // the REST "curl" mode above
		}
		modes = append(modes, f.Name)
		modes = append(modes, f.Aliases...)
	}
	return modes
}

// headOf returns the detection window of content.
func headOf(content string) []byte {
	if len(content) > source.DetectHeadBytes {
		content = content[:source.DetectHeadBytes]
	}
	return []byte(content)
}

// ingestSkipped builds the response's skipped_reasons map, omitting zero
// counts (nil when nothing was skipped).
func ingestSkipped(reasons map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range reasons {
		if v > 0 {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// resolveContent returns content from the request, decoding base64 if needed.
func resolveContent(req *IngestHTTPRequest) (string, error) {
	if req.Content != "" {
		return req.Content, nil
	}
	if req.ContentBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(req.ContentBase64)
		if err != nil {
			return "", fmt.Errorf("invalid base64 in content_base64: %w", err)
		}
		return string(data), nil
	}
	return "", ErrMissingContent
}

func (h *Handlers) ingestBurpBase64(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	if req.HTTPRequestBase64 == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "'http_request_base64' is required for burp_base64 mode")
	}

	rawReq, err := base64.StdEncoding.DecodeString(req.HTTPRequestBase64)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid base64 in http_request_base64: %w", err))
	}

	var rr *httpmsg.HttpRequestResponse
	if req.URL != "" {
		rr, err = httpmsg.ParseRawRequestWithURL(string(rawReq), req.URL)
	} else {
		rr, err = httpmsg.ParseRawRequest(string(rawReq))
	}
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("failed to parse raw request: %w", err))
	}

	// Attach response if provided
	if req.HTTPResponseBase64 != "" {
		rawResp, err := base64.StdEncoding.DecodeString(req.HTTPResponseBase64)
		if err == nil {
			resp := httpmsg.NewHttpResponse(rawResp)
			if resp != nil {
				rr = rr.WithResponse(resp)
			}
		}
	}

	rr = h.fetchResponseIfNeeded(rr)

	if !h.isIngestInScope(rr, getProjectUUID(c)) {
		return h.respondIngest(c, IngestHTTPResponse{
			ProjectUUID: getProjectUUID(c),
			Imported:    0,
			Skipped:     1,
			Message:     "filtered by scope",
		})
	}

	if _, err := h.saveRecord(ctx, rr, ingestSource(c), getProjectUUID(c)); err != nil {
		zap.L().Error("Failed to save ingested record", zap.Error(err))
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to save record: %w", err))
	}

	return h.respondIngest(c, IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    1,
		Message:     "imported 1 request",
	})
}

func (h *Handlers) ingestCurl(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, err)
	}

	rr, err := curl.ParseSingleCommand(content)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("failed to parse curl command: %w", err))
	}

	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			rr = rr.WithService(svc)
		}
	}

	rr = h.fetchResponseIfNeeded(rr)

	if !h.isIngestInScope(rr, getProjectUUID(c)) {
		return h.respondIngest(c, IngestHTTPResponse{
			ProjectUUID: getProjectUUID(c),
			Imported:    0,
			Skipped:     1,
			Message:     "filtered by scope",
		})
	}

	if _, err := h.saveRecord(ctx, rr, ingestSource(c), getProjectUUID(c)); err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to save record: %w", err))
	}

	return h.respondIngest(c, IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    1,
		Message:     "imported 1 request from curl",
	})
}

func (h *Handlers) ingestOpenAPI(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest, content, detected string) error {
	data := []byte(content)
	ext := openapi.DetectFormatFromContent(data)

	var skipped int
	acc := h.newIngestAccumulator(ctx, ingestSource(c), getProjectUUID(c))
	if req.URL == "" {
		// No base URL: the spec's servers name the hosts; only the first is
		// the scan's scope, the rest are stored as context.
		acc.deriveScope()
	}
	admit := h.ingestAdmitter(getProjectUUID(c))

	var urlOverrideSvc *httpmsg.Service
	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			urlOverrideSvc = svc
		}
	}

	// A request `url` is the base URL the spec's operations are generated
	// against; without it the spec's own servers are used. (BaseURL used to be
	// left unset, so every OpenAPI ingest with a `url` failed with the parser's
	// "base URL required" error.)
	var stats openapi.ParseStats
	opts := openapi.Options{BaseURL: req.URL, Variables: req.Variables, Stats: &stats}
	if req.URL == "" {
		opts.UseSpecServers = true
	}
	parseErr := openapi.ParseSwagger(data, ext, opts, func(rr *httpmsg.HttpRequestResponse) bool {
		if urlOverrideSvc != nil {
			rr = rr.WithService(urlOverrideSvc)
		}
		if acc.inDerivedScope(rr) {
			rr = h.fetchResponseIfNeeded(rr)
		}
		if !admit(rr) {
			skipped++
			return true
		}
		acc.add(rr)
		return true
	})

	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("failed to parse OpenAPI spec: %w", parseErr))
	}
	imported, errs := acc.finish()

	msg := fmt.Sprintf("imported %d requests from OpenAPI spec", imported)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d filtered by scope)", skipped)
	}
	if stats.SkippedOperations > 0 {
		msg += fmt.Sprintf(" (%d operations produced no request)", stats.SkippedOperations)
	}

	return h.respondIngest(c, IngestHTTPResponse{
		ProjectUUID:    getProjectUUID(c),
		Imported:       imported,
		Skipped:        skipped,
		Format:         "openapi",
		DetectedFormat: detected,
		DerivedScope:   acc.derivedPrimary(),
		ContextOnly:    acc.contextOnly,
		SkippedReasons: ingestSkipped(map[string]int{
			"out_of_scope":      skipped,
			"skipped_operation": stats.SkippedOperations,
		}),
		Errors:  errs,
		Message: msg,
	})
}

// ingestFileFormat ingests content of any registry format through the same
// parser -i uses. Parsers read files, so the content is written to a private
// temp file (0700 dir, 0600 file) that is removed afterwards.
func (h *Handlers) ingestFileFormat(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest, content, format, detected string) error {
	parser, err := source.NewParser(format)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, err)
	}

	// The request `url` is the endpoint for WSDL; for the other formats it
	// overrides each record's host, as it always has. A scope export's hosts
	// are the point of it, so they are left alone.
	overrideHost := true
	switch p := parser.(type) {
	case *postman.Format:
		// `url` also fills {{baseUrl}}/{{url}}, so a collection written
		// against a base-URL variable resolves without an explicit variables map.
		p.SetPostmanOptions(postman.Options{BaseURL: req.URL, Variables: req.Variables})
	case *wsdl.Format:
		p.SetWSDLOptions(wsdl.Options{EndpointURL: req.URL, Variables: req.Variables})
		overrideHost = false
	case *burpscope.Format:
		overrideHost = false
	}

	path, cleanup, err := writeIngestTempFile(content)
	if err != nil {
		zap.L().Error("ingest: failed to stage content", zap.Error(err))
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to stage ingest content: %w", err))
	}
	defer cleanup()

	var urlOverrideSvc *httpmsg.Service
	if overrideHost && req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			urlOverrideSvc = svc
		}
	}

	var skipped int
	acc := h.newIngestAccumulator(ctx, ingestSource(c), getProjectUUID(c))
	if urlOverrideSvc == nil && !source.IsTargetListFormat(format) {
		// A capture names many hosts; scope it to its primary one.
		acc.deriveScope()
	}
	admit := h.ingestAdmitter(getProjectUUID(c))
	parseErr := parser.Parse(path, func(rr *httpmsg.HttpRequestResponse) bool {
		if urlOverrideSvc != nil {
			rr = rr.WithService(urlOverrideSvc)
		}
		if acc.inDerivedScope(rr) {
			rr = h.fetchResponseIfNeeded(rr)
		}
		if !admit(rr) {
			skipped++
			return true
		}
		acc.add(rr)
		return true
	})
	imported, errs := acc.finish()
	if parseErr != nil {
		if imported == 0 {
			return respondErrorMsg(c, fiber.StatusBadRequest, fmt.Sprintf("failed to parse %s input: %s", format, parseErr.Error()))
		}
		// A partially parseable file keeps its good records; the error is
		// reported alongside them rather than dropped.
		errs = append(errs, "parse: "+parseErr.Error())
	}

	reasons := map[string]int{"out_of_scope": skipped}
	msg := fmt.Sprintf("imported %d requests from %s input", imported, format)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d filtered by scope)", skipped)
	}
	if p, ok := parser.(*postman.Format); ok {
		// Requests the collection could not build (an unresolved {{var}} in
		// the URL, an unparseable URL) are counted, and each unresolved
		// variable is named so the caller knows which `variables` to send.
		st := p.Stats()
		reasons["skipped_request"] = st.Skipped
		if st.Skipped > 0 {
			msg += fmt.Sprintf(" (%d requests could not be built)", st.Skipped)
		}
		names := make([]string, 0, len(st.UnresolvedVariables))
		for name := range st.UnresolvedVariables {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			v := st.UnresolvedVariables[name]
			errs = append(errs, fmt.Sprintf("unresolved variable {{%s}}: %d request(s) skipped, %d kept with the literal placeholder; pass it in \"variables\"", name, v.Skipped, v.Kept))
		}
	}

	return h.respondIngest(c, IngestHTTPResponse{
		ProjectUUID:    getProjectUUID(c),
		Imported:       imported,
		Skipped:        skipped,
		Format:         format,
		DetectedFormat: detected,
		DerivedScope:   acc.derivedPrimary(),
		ContextOnly:    acc.contextOnly,
		SkippedReasons: ingestSkipped(reasons),
		Errors:         errs,
		Message:        msg,
	})
}

// writeIngestTempFile stages content in a fresh private directory and returns
// the file path and a cleanup func that removes the directory.
func writeIngestTempFile(content string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "vigolium-ingest-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0o700); err != nil {
		cleanup()
		return "", func() {}, err
	}
	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func (h *Handlers) ingestURL(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest) error {
	content, err := resolveContent(req)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, err)
	}

	rr, err := httpmsg.GetRawRequestFromURL(strings.TrimSpace(content))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("failed to create request from URL: %w", err))
	}

	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			rr = rr.WithService(svc)
		}
	}

	rr = h.fetchResponseIfNeeded(rr)

	if !h.isIngestInScope(rr, getProjectUUID(c)) {
		return h.respondIngest(c, IngestHTTPResponse{
			ProjectUUID: getProjectUUID(c),
			Imported:    0,
			Skipped:     1,
			Message:     "filtered by scope",
		})
	}

	if _, err := h.saveRecord(ctx, rr, ingestSource(c), getProjectUUID(c)); err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to save record: %w", err))
	}

	return h.respondIngest(c, IngestHTTPResponse{
		ProjectUUID: getProjectUUID(c),
		Imported:    1,
		Message:     "imported 1 request from URL",
	})
}

func (h *Handlers) ingestURLFile(c fiber.Ctx, ctx context.Context, req *IngestHTTPRequest, content, detected string) error {
	// Never silent: content that is mostly not URLs (a HAR posted as
	// url_file, say) is refused with the format it resembles, instead of
	// answering 200 with a line of errors per JSON brace.
	if err := source.CheckURLListContent("content", []byte(content), detected == ""); err != nil {
		var ue *source.UnparsedInputError
		msg := err.Error()
		if errors.As(err, &ue) {
			msg = fmt.Sprintf("input_unparsed: content is not a URL list (%d of %d non-comment lines are not URLs)", ue.Failed, ue.Lines)
			if ue.Candidate != "" {
				msg += fmt.Sprintf("; it looks like %s, set input_mode to %q or \"auto\"", ue.Candidate, ue.Candidate)
			}
		}
		return respondErrorMsg(c, fiber.StatusBadRequest, msg)
	}

	var skipped int
	var parseErrors []string // per-line parse errors keep their line context
	acc := h.newIngestAccumulator(ctx, ingestSource(c), getProjectUUID(c))
	admit := h.ingestAdmitter(getProjectUUID(c))

	var urlOverrideSvc *httpmsg.Service
	if req.URL != "" {
		if svc, svcErr := httpmsg.ParseService(req.URL); svcErr == nil {
			urlOverrideSvc = svc
		}
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !urls.IsTargetLine(line) {
			continue
		}

		rr, err := httpmsg.GetRawRequestFromURL(line)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s: %s", line, err.Error()))
			continue
		}

		if urlOverrideSvc != nil {
			rr = rr.WithService(urlOverrideSvc)
		}

		rr = h.fetchResponseIfNeeded(rr)

		if !admit(rr) {
			skipped++
			continue
		}

		acc.add(rr)
	}
	imported, accErrs := acc.finish()
	errs := append(parseErrors, accErrs...)

	msg := fmt.Sprintf("imported %d requests from URL list", imported)
	if skipped > 0 {
		msg += fmt.Sprintf(" (%d filtered by scope)", skipped)
	}

	return h.respondIngest(c, IngestHTTPResponse{
		ProjectUUID:    getProjectUUID(c),
		Imported:       imported,
		Skipped:        skipped,
		Format:         "urls",
		DetectedFormat: detected,
		SkippedReasons: ingestSkipped(map[string]int{
			"out_of_scope":  skipped,
			"unparsed_line": len(parseErrors),
		}),
		Errors:  errs,
		Message: msg,
	})
}

// respondIngest writes an ingest result, naming the scan-on-receive scan that
// will process the records when the server runs one.
func (h *Handlers) respondIngest(c fiber.Ctx, resp IngestHTTPResponse) error {
	if h.config.ScanOnReceive && h.repo != nil && resp.Imported > 0 {
		ctx, cancel := context.WithTimeout(c.Context(), 2*time.Second)
		defer cancel()
		if s, err := h.repo.LatestScanOnReceiveScan(ctx, resp.ProjectUUID); err == nil && s != nil {
			sor := &IngestScanOnReceive{ScanUUID: s.UUID, CursorUUID: s.CursorUUID, ProcessedCount: s.ProcessedCount}
			if !s.CursorAt.IsZero() {
				sor.CursorAt = s.CursorAt.UTC().Format(time.RFC3339Nano)
			}
			resp.ScanOnReceive = sor
		}
	}
	return c.JSON(resp)
}
