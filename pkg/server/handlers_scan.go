package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// resolveAPIModules resolves module patterns and tags into a list of module IDs.
func resolveAPIModules(modulePatterns, moduleTags []string) []string {
	hasModules := len(modulePatterns) > 0
	hasTags := len(moduleTags) > 0

	if !hasModules && !hasTags {
		return []string{"all"}
	}

	seen := make(map[string]struct{})
	var result []string

	addUnique := func(ids []string) {
		for _, id := range ids {
			if id == "all" {
				return
			}
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				result = append(result, id)
			}
		}
	}

	if hasModules {
		resolved := modules.ResolveModulePatterns(modulePatterns)
		if len(resolved) == 1 && resolved[0] == "all" {
			return resolved
		}
		if len(resolved) == 0 {
			addUnique(modulePatterns)
		} else {
			addUnique(resolved)
		}
	}

	if hasTags {
		tagResolved := modules.ResolveModuleTags(moduleTags)
		addUnique(tagResolved)
	}

	if len(result) == 0 {
		return []string{"all"}
	}
	return result
}

// applyAPIModuleSelection fills opts' module selection from a request's
// modules / module_tags: the resolved built-in IDs, plus the raw patterns and
// tags the runner re-applies to the JS/YAML extensions it loads — the same
// split the CLI makes for -m / --module-tag (applyModuleSelection), so a REST
// scan narrowed to "xss" narrows the extensions too instead of running every
// loaded one.
func applyAPIModuleSelection(opts *types.Options, modulePatterns, moduleTags []string) {
	opts.Modules = resolveAPIModules(modulePatterns, moduleTags)
	opts.ModulePatterns = append([]string(nil), modulePatterns...)
	opts.ModuleTags = append([]string(nil), moduleTags...)
}

// validateRunScanRequest validates the RunScanRequest fields.
func validateRunScanRequest(req RunScanRequest) error {
	if req.Strategy != "" {
		switch req.Strategy {
		case "lite", "balanced", "deep":
		default:
			return fmt.Errorf("invalid strategy %q; valid values: lite, balanced, deep", req.Strategy)
		}
	}

	if req.Only != "" {
		for _, p := range strings.Split(req.Only, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			// The phase vocabulary has one owner (runner.nativePhaseVocabulary);
			// a local copy of the valid set here is what let the REST API reject
			// a spelling the CLI accepted.
			if !runner.IsOnlyPhaseSpelling(p) {
				return fmt.Errorf("invalid only %q; valid phases: %s", p, runner.ValidOnlyPhasesDesc)
			}
		}
	}

	if req.Only != "" && len(req.Skip) > 0 {
		return fmt.Errorf("only and skip are mutually exclusive; use one or the other")
	}

	if len(req.Skip) > 0 {
		for _, phase := range req.Skip {
			// Same table as the CLI: a hand-listed set here is what kept the REST
			// API rejecting phases (probe, extension, port-sweep) --skip accepted.
			if !runner.IsSkippablePhaseSpelling(phase) {
				return fmt.Errorf("invalid skip value %q; valid phases: %s", phase, runner.ValidSkipPhasesDesc)
			}
		}
	}

	if req.ScopeOrigin != "" && !config.ValidCLIOriginMode(req.ScopeOrigin) {
		return fmt.Errorf("invalid scope_origin %q; valid values: %s", req.ScopeOrigin, strings.Join(config.CLIOriginModes, ", "))
	}

	if req.HeuristicsCheck != "" {
		switch req.HeuristicsCheck {
		case "none", "basic", "advanced":
		default:
			return fmt.Errorf("invalid heuristics_check %q; valid values: none, basic, advanced", req.HeuristicsCheck)
		}
	}

	if req.Timeout != "" {
		if _, err := time.ParseDuration(req.Timeout); err != nil {
			return fmt.Errorf("invalid timeout %q: %w", req.Timeout, err)
		}
	}

	if req.ScanningMaxDuration != "" {
		if _, err := time.ParseDuration(req.ScanningMaxDuration); err != nil {
			return fmt.Errorf("invalid scanning_max_duration %q: %w", req.ScanningMaxDuration, err)
		}
	}

	if req.Concurrency < 0 {
		return fmt.Errorf("concurrency must be > 0")
	}

	if req.MaxPerHost < 0 {
		return fmt.Errorf("max_per_host must be > 0")
	}

	if req.MaxRequests < 0 {
		return fmt.Errorf("max_requests must be >= 0 (0 = unlimited)")
	}
	if req.MaxRequestsPerHost < 0 {
		return fmt.Errorf("max_requests_per_host must be >= 0 (0 = unlimited)")
	}

	return nil
}

// resolveAPIOutputFormats validates and normalizes the output_formats request
// field against the REST surface of the output format table (aliases and case
// folded, e.g. "MD" → "markdown"). "jsonl" (the runner's live stream) is always
// produced; every other value must also be one of reportFormats, the report
// formats this server has a renderer for (ServerConfig.ReportFormats), so a
// requested format is never accepted and then silently not produced.
// Returns a deduplicated slice of canonical names. Empty input yields nil.
func resolveAPIOutputFormats(formats, reportFormats []string) ([]string, error) {
	if len(formats) == 0 {
		return nil, nil
	}
	supported := append([]string{"jsonl"}, reportFormats...)
	seen := make(map[string]struct{}, len(formats))
	out := make([]string, 0, len(formats))
	for _, f := range formats {
		if strings.TrimSpace(f) == "" {
			continue
		}
		of, err := output.Lookup(f, output.SurfaceREST)
		if err != nil || !slices.Contains(supported, of.Name) {
			return nil, fmt.Errorf("invalid output_format %q; supported: %s", f, strings.Join(supported, ", "))
		}
		if _, dup := seen[of.Name]; dup {
			continue
		}
		seen[of.Name] = struct{}{}
		out = append(out, of.Name)
	}
	return out, nil
}

// scanOutputs is where a REST scan's requested output files live:
// <sessions>/<scan>/output.<ext>, one per format. The runner writes the live
// jsonl stream there; runBackgroundScan renders the report formats after the
// scan and uploads whatever was requested.
type scanOutputs struct {
	base    string
	formats []string
}

// path returns the file a format is written to.
func (o scanOutputs) path(format string) string {
	return types.FormatOutputPath(o.base, format)
}

// buildRunScanOptions builds the request-shaped types.Options for a
// RunScanRequest: targets, modules, transport knobs and the pace values the
// caller typed. Intensity, profile, strategy and scanning_pace are resolved
// afterwards by ResolveRunScanRequest through the shared runner functions.
func buildRunScanOptions(req RunScanRequest, projectUUID string, serverConcurrency int) (*types.Options, error) {
	opts := types.DefaultOptions()
	opts.Targets = req.Targets
	applyAPIModuleSelection(opts, req.Modules, req.ModuleTags)
	opts.ProjectUUID = projectUUID
	applyRequestPace(opts, serverConcurrency, req.Concurrency, req.RateLimit, req.MaxPerHost)

	if req.Timeout != "" {
		d, err := time.ParseDuration(req.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
		opts.Timeout = d
	}
	if req.ScanningMaxDuration != "" {
		d, err := time.ParseDuration(req.ScanningMaxDuration)
		if err != nil {
			return nil, fmt.Errorf("invalid scanning_max_duration: %w", err)
		}
		opts.ScanMaxDuration = d
	}

	if len(req.Headers) > 0 {
		headers := make([]string, 0, len(req.Headers))
		for k, v := range req.Headers {
			headers = append(headers, k+": "+v)
		}
		opts.Headers = headers
	}

	if req.ScopeOrigin != "" {
		opts.ScopeOriginMode = req.ScopeOrigin
	}
	opts.MaxRequests = req.MaxRequests
	opts.MaxRequestsPerHost = req.MaxRequestsPerHost
	return opts, nil
}

// ResolveRunScanRequest resolves a POST /api/scans/run body into the options the
// runner will use, applying the same scan-options resolution the CLI runs
// (runner/strategy_apply.go): profile → settings overrides → strategy (explicit
// rate limit, phases, pace ceiling, heuristics) → only/skip → scanning_pace.
//
// settings is mutated and must be the request's own clone. Every error is a
// client error (an unknown profile, strategy or phase, an invalid pace config).
// serverConcurrency is the server's worker default, used when the request and
// scanning_pace leave concurrency unset.
func ResolveRunScanRequest(settings *config.Settings, serverConcurrency int, req RunScanRequest, projectUUID string) (*types.Options, runner.ResolvedStrategy, error) {
	opts, err := buildRunScanOptions(req, projectUUID, serverConcurrency)
	if err != nil {
		return nil, runner.ResolvedStrategy{}, err
	}
	explicit := requestExplicitPace(req.Concurrency, req.RateLimit, req.MaxPerHost)
	explicit.MaxRequests = req.MaxRequests > 0
	explicit.MaxRequestsPerHost = req.MaxRequestsPerHost > 0
	strategy, err := resolveRequestStrategy(settings, opts, req.Intensity, req.ScanningProfile, runner.StrategyRequest{
		Name:            req.Strategy,
		HeuristicsCheck: req.HeuristicsCheck,
		Explicit:        explicit,
	})
	if err != nil {
		return nil, runner.ResolvedStrategy{}, err
	}
	opts.OnlyPhase = req.Only
	// Copy req.Skip — ApplyNativePhaseSelection normalizes the slice in place.
	opts.SkipPhases = append([]string(nil), req.Skip...)
	if err := runner.ApplyNativePhaseSelection(opts, func(enabled bool) {
		settings.DynamicAssessment.Extensions.Enabled = enabled
	}); err != nil {
		return nil, runner.ResolvedStrategy{}, err
	}
	if err := runner.ApplyScanPace(settings, opts, explicit); err != nil {
		return nil, runner.ResolvedStrategy{}, err
	}
	return opts, strategy, nil
}

// HandleRunScan handles POST /api/scans/run — triggers an async target-based scan.
// This route only accepts target URLs. Use POST /api/scan-all-records to scan DB records.
func (h *Handlers) HandleRunScan(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusBadRequest, ErrDatabaseRequired)
	}

	var req RunScanRequest
	if len(c.Body()) > 0 {
		if err := c.Bind().JSON(&req); err != nil {
			return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		}
	}

	// Merge urls into targets
	if len(req.URLs) > 0 {
		req.Targets = append(req.Targets, req.URLs...)
	}

	if len(req.Targets) == 0 {
		return respondErrorMsg(c, fiber.StatusBadRequest, "at least one target URL is required (use 'targets' or 'urls' field)")
	}

	if err := validateRunScanRequest(req); err != nil {
		return respondError(c, fiber.StatusBadRequest, err)
	}

	projectUUID := getProjectUUID(c)

	// The project's settings (global → X-Project-UUID's overlay), with
	// persist_logs forced so API-triggered scans always produce a runtime.log
	// for `vigolium log <uuid>`. The request's profile and fields are layered
	// on by ResolveRunScanRequest.
	projectSettings, err := h.settingsForProject(projectUUID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, err)
	}
	settings := forceNativePersistLogs(projectSettings)

	// Profile, strategy, phase selection and pace resolve exactly as the CLI
	// resolves them. Every failure here — an unknown profile or strategy, an
	// invalid pace config — is the caller's to fix, so it is a 400.
	opts, strategy, err := ResolveRunScanRequest(settings, h.config.Concurrency, req, projectUUID)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, err)
	}
	resolved := newScanResolved(strategy.Name, opts)

	resolvedModules := opts.Modules
	scanID := req.ScanUUID
	if scanID == "" {
		scanID = uuid.New().String()
	}
	// Pin the runner's scan UUID to the API-issued one so findings, runtime.log,
	// and the storage_url upload path all key off the same identifier the
	// caller polls. Without this the runner generates its own UUID, the
	// runtime.log lands at a path uploadNativeScanResults can't find, and
	// /api/findings?scan_uuid=<api-uuid> returns nothing.
	opts.ScanUUID = scanID
	// The server owns the scan record's pending/queued/running lifecycle below;
	// tell the runner not to create a competing row, but let it keep ownership of
	// the single terminal CompleteScan.
	opts.ManagedScanRecord = true

	formats, err := resolveAPIOutputFormats(req.OutputFormats, h.config.ReportFormats)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, err)
	}
	var outputs scanOutputs
	if len(formats) > 0 {
		// Output base path is fixed under the scan's session dir so the post-scan
		// renderer and uploadNativeScanResults know where each format's file is.
		outputs = scanOutputs{
			base: filepath.Join(
				settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(),
				scanID,
				"output",
			),
			formats: formats,
		}
		opts.OutputFormats = formats
		// The runner only writes the live jsonl stream (report formats are
		// rendered by runBackgroundScan). Pointing -o at the jsonl path makes the
		// single-format case (literal -o) and the multi-format case (base + .jsonl)
		// land on the same file.
		opts.Output = outputs.path("jsonl")
	}

	// Detached on purpose: these writes register a scan that will run in a
	// background goroutine (see go h.runBackgroundScan below). The record must
	// persist even if this client disconnects right after kicking the scan off,
	// so it is deliberately not tied to the request context.
	ctx := context.Background()

	scanMode := "target"

	// Dry run: validate and return without persisting a scan record or building a
	// runner. Nothing runs, so leaving no row (rather than a permanently "pending"
	// one) is the honest result.
	if req.DryRun {
		return c.Status(fiber.StatusOK).JSON(ScanResponse{
			ProjectUUID:  projectUUID,
			ScanUUID:     scanID,
			Status:       "dry_run",
			Message:      "scan validated (dry run)",
			TargetsCount: len(req.Targets),
			ScanMode:     scanMode,
			Resolved:     resolved,
		})
	}

	newScanRecord := func(status string) *database.Scan {
		return &database.Scan{
			UUID:        scanID,
			ProjectUUID: projectUUID,
			Name:        "api-scan",
			Status:      status,
			Modules:     strings.Join(resolvedModules, ","),
			ScanSource:  "api",
			ScanMode:    scanMode,
			StartedAt:   time.Now(),
		}
	}

	// Admission before heavyweight allocation: decide the outcome (reject / queue /
	// run) first, and only then build a runner and persist a record. A rejected
	// submission (queue full / project busy without a queue) leaves no pending row
	// and no leaked runner. qCh is non-nil once we've decided to queue this scan.
	h.scanMu.Lock()
	st := h.getProjectScanState(projectUUID)

	var qCh chan *queuedScan
	if st.running {
		// Project busy — queue if enabled, else reject.
		if h.config.ScanQueueCapacity <= 0 {
			h.scanMu.Unlock()
			return respondError(c, fiber.StatusConflict, ErrScanAlreadyRunning)
		}
		ch, ok := h.scanQueues[projectUUID]
		if !ok {
			ch = make(chan *queuedScan, h.config.ScanQueueCapacity)
			h.scanQueues[projectUUID] = ch
			go h.scanQueueWorker(projectUUID, ch)
		}
		if len(ch) >= h.config.ScanQueueCapacity {
			h.scanMu.Unlock()
			return respondErrorMsg(c, fiber.StatusTooManyRequests, "scan queue full for this project")
		}
		qCh = ch
	}

	// Admitted (run or queue): build the runner and persist the record once.
	status := "running"
	if qCh != nil {
		status = "queued"
	}
	scanRunner, err := runner.New(opts)
	if err != nil {
		h.scanMu.Unlock()
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to create scan runner: %w", err))
	}
	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(h.repo)
	if err := h.repo.CreateScan(ctx, newScanRecord(status)); err != nil {
		h.scanMu.Unlock()
		scanRunner.Discard()
		return respondScanPinError(c, err)
	}

	if qCh != nil {
		qCh <- &queuedScan{
			scanID:        scanID,
			runner:        scanRunner,
			projectUUID:   projectUUID,
			enqueued:      time.Now(),
			uploadResults: req.UploadResults,
			outputs:       outputs,
		}
		position := len(qCh)
		h.scanMu.Unlock()
		return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
			ProjectUUID:  projectUUID,
			ScanUUID:     scanID,
			Status:       "queued",
			Message:      fmt.Sprintf("scan queued (position %d)", position),
			TargetsCount: len(req.Targets),
			ScanMode:     scanMode,
			Resolved:     resolved,
		})
	}

	st.runner = scanRunner
	st.running = true
	st.scanID = scanID
	h.scanMu.Unlock()

	go h.runBackgroundScan(scanID, scanRunner, projectUUID, req.UploadResults, outputs)

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID:  projectUUID,
		ScanUUID:     scanID,
		Status:       "running",
		Message:      "scan started",
		TargetsCount: len(req.Targets),
		ScanMode:     scanMode,
		Resolved:     resolved,
	})
}

// HandleListScans handles GET /api/scans — returns paginated scan history.
func (h *Handlers) HandleListScans(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	limit := 50
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 500 {
		limit = 500
	}

	offset := 0
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	projectUUID := getProjectUUID(c)
	scans, total, err := h.repo.ListScans(c.Context(), projectUUID, limit, offset)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to list scans: %w", err))
	}

	return respondList(c, PaginatedResponse{
		ProjectUUID: projectUUID,
		Data:        buildScanViews(scans),
		Total:       total,
		Limit:       limit,
		Offset:      offset,
		HasMore:     int64(offset+limit) < total,
	})
}

// buildScanViews wraps each scan in a display-oriented view that renders the
// modules list as "all" when every built-in active module is enabled,
// substitutes a placeholder Target for ingest-grouped scans, and attaches
// active/passive module counts.
func buildScanViews(scans []*database.Scan) []*database.ScanView {
	allActiveCount := len(modules.GetActiveModulesID())
	allPassiveCount := len(modules.GetPassiveModulesID())

	views := make([]*database.ScanView, len(scans))
	for i, s := range scans {
		active := splitModuleCSV(s.Modules)
		modulesDisplay := s.Modules
		if allActiveCount > 0 && len(active) >= allActiveCount {
			modulesDisplay = "all"
		}
		views[i] = &database.ScanView{
			Scan:                s,
			Target:              displayScanTarget(s),
			Modules:             modulesDisplay,
			TotalActiveModules:  len(active),
			TotalPassiveModules: allPassiveCount,
		}
	}
	return views
}

// displayScanTarget substitutes a human-readable placeholder for scans that
// have no single target URL — scan-on-receive and catchup scans group traffic
// from the ingest stream rather than scanning one endpoint.
func displayScanTarget(s *database.Scan) string {
	if s.Target != "" {
		return s.Target
	}
	switch s.ScanSource {
	case "scan-on-receive", "server-catchup":
		return "<grouped-from-ingest-stream>"
	}
	return ""
}

func splitModuleCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// HandleGetScan handles GET /api/scans/:uuid — returns a single scan by UUID.
func (h *Handlers) HandleGetScan(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	uuid := c.Params("uuid")
	if uuid == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "missing uuid parameter")
	}

	scan, err := h.repo.GetScanByUUID(c.Context(), uuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondError(c, fiber.StatusNotFound, ErrScanNotFound)
		}
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to retrieve scan: %w", err))
	}
	if !inRequestProject(c, scan.ProjectUUID) {
		return respondError(c, fiber.StatusNotFound, ErrScanNotFound)
	}

	return c.JSON(buildScanViews([]*database.Scan{scan})[0])
}

// HandleDeleteScan handles DELETE /api/scans/:uuid — deletes a scan record.
func (h *Handlers) HandleDeleteScan(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	scanUUID := c.Params("uuid")
	if scanUUID == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "missing uuid parameter")
	}

	// Verify scan exists and belongs to the request's active project.
	scan, err := h.repo.GetScanByUUID(c.Context(), scanUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondError(c, fiber.StatusNotFound, ErrScanNotFound)
		}
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to retrieve scan: %w", err))
	}
	if !inRequestProject(c, scan.ProjectUUID) {
		return respondError(c, fiber.StatusNotFound, ErrScanNotFound)
	}

	if err := h.repo.DeleteScan(c.Context(), scanUUID); err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to delete scan: %w", err))
	}

	return c.JSON(fiber.Map{
		"project_uuid": getProjectUUID(c),
		"message":      "scan deleted",
		"uuid":         scanUUID,
	})
}

// HandleStopScan handles POST /api/scans/:uuid/stop — stops a specific running scan.
func (h *Handlers) HandleStopScan(c fiber.Ctx) error {
	scanUUID := c.Params("uuid")
	if scanUUID == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "missing uuid parameter")
	}

	// Scope to the request's active project (X-Project-UUID): a scan is stopped
	// only through the project that owns it, matching HandleGetScan/HandleDeleteScan.
	projectUUID := getProjectUUID(c)
	h.scanMu.Lock()
	st, ok := h.scanStates[projectUUID]
	if !ok || !st.running || st.scanID != scanUUID {
		h.scanMu.Unlock()
		return h.requestForeignScanStop(c, projectUUID, scanUUID)
	}
	scanRunner := st.runner
	h.scanMu.Unlock()

	// Close outside the lock: it cancels and waits (bounded) for the scan to
	// unwind, so holding scanMu would stall every other scan operation meanwhile.
	if scanRunner != nil {
		scanRunner.Close()
	}
	return c.JSON(ScanStatusResponse{
		ProjectUUID: projectUUID,
		ScanUUID:    scanUUID,
		Running:     true,
		Status:      "cancelling",
		Message:     "scan stop requested, workers finishing current tasks",
	})
}

// requestForeignScanStop stops a scan this server does not run — a CLI scan
// writing the same store, or one another server runs — by writing a stop
// request on its row, which that scan's heartbeat picks up within one beat.
// 202: the request is recorded, the scan has not stopped yet.
func (h *Handlers) requestForeignScanStop(c fiber.Ctx, projectUUID, scanUUID string) error {
	notRunning := func() error {
		return respondErrorMsg(c, fiber.StatusConflict, "scan "+scanUUID+" is not running")
	}
	if h.repo == nil {
		return notRunning()
	}
	scan, err := h.repo.GetScanByUUID(c.Context(), scanUUID)
	if err != nil || scan == nil || !inRequestProject(c, scan.ProjectUUID) || scan.Status != "running" {
		return notRunning()
	}
	ok, err := h.repo.RequestScanStop(c.Context(), scanUUID, "rest api")
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("record stop request: %w", err))
	}
	if !ok {
		return notRunning()
	}
	return c.Status(fiber.StatusAccepted).JSON(ScanStatusResponse{
		ProjectUUID: projectUUID,
		ScanUUID:    scanUUID,
		Running:     true,
		Status:      "stop_requested",
		Message:     "stop requested: the scan runs in another process and stops at its next heartbeat (within ~10s)",
	})
}

// HandleScanStatus handles GET /api/scan/status — returns current scan state.
// Accepts optional ?project= query param to check a specific project.
func (h *Handlers) HandleScanStatus(c fiber.Ctx) error {
	projectUUID := getProjectUUID(c)
	queryProject := c.Query("project")
	if queryProject != "" {
		projectUUID = queryProject
	}

	h.scanMu.Lock()
	st := h.scanStates[projectUUID]
	var running bool
	var scanID string
	var r *runner.Runner
	if st != nil && st.running {
		running = true
		scanID = st.scanID
		r = st.runner
	}
	h.scanMu.Unlock()

	if running {
		// "pausing" until the workers have quiesced, then "paused".
		status := runner.PauseStateRunning
		if r != nil {
			status = r.PauseState()
		}
		return c.JSON(ScanStatusResponse{
			ProjectUUID: projectUUID,
			ScanUUID:    scanID,
			Running:     true,
			Status:      status,
		})
	}

	return c.JSON(ScanStatusResponse{
		ProjectUUID: projectUUID,
		Running:     false,
		Status:      "idle",
	})
}

// HandlePauseScan handles POST /api/scans/:uuid/pause — pauses a running scan.
func (h *Handlers) HandlePauseScan(c fiber.Ctx) error {
	scanUUID := c.Params("uuid")
	if scanUUID == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "missing uuid parameter")
	}

	// Scope to the request's active project (see HandleStopScan).
	projectUUID := getProjectUUID(c)
	h.scanMu.Lock()
	st, ok := h.scanStates[projectUUID]
	if !ok || !st.running || st.scanID != scanUUID || st.runner == nil {
		h.scanMu.Unlock()
		return respondErrorMsg(c, fiber.StatusConflict, "scan "+scanUUID+" is not running")
	}
	r := st.runner
	if r.IsPaused() {
		h.scanMu.Unlock()
		return respondErrorMsg(c, fiber.StatusConflict, "scan is already paused")
	}
	// Pause never blocks (it only stops dispatch/admission), but release the
	// server-wide scan lock before the DB write anyway: stop and status for
	// every project wait on it.
	r.Pause()
	h.scanMu.Unlock()
	if h.repo != nil {
		_ = h.repo.PauseScan(c.Context(), scanUUID)
	}
	return c.JSON(ScanStatusResponse{
		ProjectUUID: projectUUID,
		ScanUUID:    scanUUID,
		Running:     true,
		Status:      r.PauseState(),
		Message:     "scan pausing: no new work is dispatched; in-flight items finish first (status reports paused once they have)",
	})
}

// HandleResumeScan handles POST /api/scans/:uuid/resume — resumes a paused scan.
func (h *Handlers) HandleResumeScan(c fiber.Ctx) error {
	scanUUID := c.Params("uuid")
	if scanUUID == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "missing uuid parameter")
	}

	// Scope to the request's active project (see HandleStopScan).
	projectUUID := getProjectUUID(c)
	h.scanMu.Lock()
	defer h.scanMu.Unlock()

	st, ok := h.scanStates[projectUUID]
	if !ok || !st.running || st.scanID != scanUUID || st.runner == nil {
		return respondErrorMsg(c, fiber.StatusConflict, "scan "+scanUUID+" is not running")
	}
	if !st.runner.IsPaused() {
		return respondErrorMsg(c, fiber.StatusConflict, "scan is not paused")
	}
	st.runner.Resume()
	if h.repo != nil {
		_ = h.repo.ResumeScan(c.Context(), scanUUID)
	}
	return c.JSON(ScanStatusResponse{
		ProjectUUID: projectUUID,
		ScanUUID:    scanUUID,
		Running:     true,
		Status:      "running",
		Message:     "scan resumed",
	})
}

// HandleGetScanLogs handles GET /api/scans/:uuid/logs — returns scan logs.
//
// Response format is chosen by the content source in the same priority order
// as the `vigolium log <uuid>` CLI command:
//
//  1. If {sessions_dir}/{scanUUID}/runtime.log exists, serve its contents as
//     text/plain. Matches what the operator sees when tailing the CLI log.
//     ANSI colors are preserved by default; pass ?strip=1 to remove them.
//
//  2. Otherwise, fall back to the scan_logs database table and return the
//     structured JSON envelope ({"logs": [...], "total": N}) that older
//     clients depend on. This fallback is the legacy path used by scans
//     that predate runtime.log persistence.
func (h *Handlers) HandleGetScanLogs(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	scanUUID := c.Params("uuid")
	if scanUUID == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "missing uuid parameter")
	}

	// Verify scan exists and belongs to the request's active project.
	scan, err := h.repo.GetScanByUUID(c.Context(), scanUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondError(c, fiber.StatusNotFound, ErrScanNotFound)
		}
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to retrieve scan: %w", err))
	}
	if !inRequestProject(c, scan.ProjectUUID) {
		return respondError(c, fiber.StatusNotFound, ErrScanNotFound)
	}

	// Prefer the on-disk runtime.log — that's what /api/scan-request and
	// /api/scan-url produce today, and it matches what the CLI `vigolium log`
	// command streams.
	sessionsDir := config.ExpandPath("~/.vigolium/native-sessions/")
	if h.settings != nil {
		sessionsDir = h.settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()
	}
	if logPath := resolveRuntimeLogPath(filepath.Join(sessionsDir, scanUUID)); logPath != "" {
		return sendLogTail(c, logPath, parseBoolParam(c.Query("strip")))
	}

	// Fallback: structured DB logs. Preserved for clients that relied on the
	// JSON envelope before runtime.log was the primary log source.
	limit := 100
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	offset := 0
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}
	level := c.Query("level")
	phase := c.Query("phase")

	logs, total, err := h.repo.ListScanLogs(c.Context(), scanUUID, level, phase, limit, offset)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to retrieve scan logs: %w", err))
	}

	return respondBespokeList(c, fiber.Map{
		"project_uuid": getProjectUUID(c),
		"logs":         logs,
		"total":        total,
	}, PaginatedResponse{
		ProjectUUID: getProjectUUID(c),
		Data:        logs,
		Total:       int64(total),
		Limit:       limit,
		Offset:      offset,
	}, nil)
}

// runBackgroundScan runs the scan in a background goroutine. Requested report
// formats (outputs) are rendered from the database once the scan finishes. When
// uploadResults is true and storage is configured, the scan's runtime.log and
// requested output files are bundled and uploaded to
// <projectUUID>/native-scans/<scanID>/results.tar.gz after the scan completes.
func (h *Handlers) runBackgroundScan(scanID string, scanRunner *runner.Runner, projectUUID string, uploadResults bool, outputs scanOutputs) {
	defer func() {
		h.scanMu.Lock()
		if st, ok := h.scanStates[projectUUID]; ok {
			st.running = false
			st.runner = nil
			st.scanID = ""
		}
		h.scanMu.Unlock()
	}()

	start := time.Now()
	zap.L().Info("Background scan started", zap.String("scan_uuid", scanID))

	var errMsg string
	if err := scanRunner.RunNativeScan(); err != nil {
		errMsg = err.Error()
		zap.L().Error("Background scan failed", zap.String("scan_uuid", scanID), zap.Error(err))
	}

	scanRunner.Close()

	elapsed := time.Since(start)
	zap.L().Info("Background scan completed",
		zap.String("scan_uuid", scanID),
		zap.Duration("elapsed", elapsed))

	// The runner is the single finalization owner: RunNativeScan writes the
	// terminal status (on a detached context, so a stop can't fail it) and marks
	// itself finalized. Only fall back to a server-side completion when the runner
	// never reached its finalizer (e.g. infrastructure setup failed before the
	// scan record's completion defer was registered), so we never overwrite the
	// runner's truthful cancelled/failed outcome with "completed".
	if !scanRunner.Finalized() {
		// Background goroutine, no request in scope: the originating request
		// returned 202 long ago. Use a fresh context so finalizing the scan record
		// can't be cancelled by a client disconnect.
		ctx := context.Background()
		if err := h.repo.CompleteScan(ctx, scanID, errMsg); err != nil {
			zap.L().Error("Failed to complete scan record", zap.String("scan_uuid", scanID), zap.Error(err))
		}
	}

	h.renderScanReports(projectUUID, scanID, outputs)

	if uploadResults {
		h.uploadNativeScanResults(projectUUID, scanID, outputs)
	}

	webhook.FireNativeScan(h.settings, h.repo, scanID)
}

// renderScanReports writes every requested report format (everything but the
// live jsonl stream) for a finished REST scan, through the same generator the
// CLI's `scan --format` uses, scoped to this scan. A failure is logged at error
// level naming the format and path; the upload that follows reports the file
// as missing rather than silently bundling without it.
func (h *Handlers) renderScanReports(projectUUID, scanID string, outputs scanOutputs) {
	for _, format := range outputs.formats {
		if format == "jsonl" {
			continue
		}
		path := outputs.path(format)
		if h.config.RenderReport == nil || h.db == nil {
			zap.L().Error("Cannot render requested scan report: no report renderer configured",
				zap.String("scan_uuid", scanID), zap.String("format", format))
			continue
		}
		if err := h.config.RenderReport(context.Background(), h.db, format, path, projectUUID, scanID); err != nil {
			zap.L().Error("Failed to render requested scan report",
				zap.String("scan_uuid", scanID), zap.String("format", format),
				zap.String("path", path), zap.Error(err))
			continue
		}
		zap.L().Info("Rendered scan report",
			zap.String("scan_uuid", scanID), zap.String("format", format), zap.String("path", path))
	}
}
