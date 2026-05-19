package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
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

// validPhases is the set of valid phase names for --only validation.
var validPhases = map[string]struct{}{
	"ingestion": {}, "discovery": {}, "external-harvest": {},
	"spidering": {}, "known-issue-scan": {}, "dynamic-assessment": {},
	"extension": {},
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
			normalized := runner.NormalizeNativePhase(p)
			if _, ok := validPhases[normalized]; !ok {
				return fmt.Errorf("invalid only %q; valid phases: %s", p, runner.ValidOnlyPhasesDesc)
			}
		}
	}

	if req.Only != "" && len(req.Skip) > 0 {
		return fmt.Errorf("only and skip are mutually exclusive; use one or the other")
	}

	if len(req.Skip) > 0 {
		for _, phase := range req.Skip {
			normalized := runner.NormalizeNativePhase(phase)
			switch normalized {
			case "discovery", "ingestion", "external-harvest", "spidering", "known-issue-scan", "dynamic-assessment":
			default:
				return fmt.Errorf("invalid skip value %q; valid phases: %s", phase, runner.ValidSkipPhasesDesc)
			}
		}
	}

	if req.ScopeOrigin != "" {
		switch req.ScopeOrigin {
		case "all", "relaxed", "balanced", "strict":
		default:
			return fmt.Errorf("invalid scope_origin %q; valid values: all, relaxed, balanced, strict", req.ScopeOrigin)
		}
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

	return nil
}

// resolveAPIOutputFormats validates and normalizes the output_formats request
// field. Only "jsonl" and "html" are accepted; any other value is rejected.
// Returns a deduplicated, lowercased slice. Empty input yields a nil slice.
func resolveAPIOutputFormats(formats []string) ([]string, error) {
	if len(formats) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(formats))
	out := make([]string, 0, len(formats))
	for _, f := range formats {
		norm := strings.ToLower(strings.TrimSpace(f))
		if norm == "" {
			continue
		}
		if norm != "jsonl" && norm != "html" {
			return nil, fmt.Errorf("invalid output_format %q; supported: jsonl, html", f)
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	return out, nil
}

// buildRunScanOptions builds types.Options from the RunScanRequest.
func (h *Handlers) buildRunScanOptions(req RunScanRequest, projectUUID string) (*types.Options, error) {
	opts := types.DefaultOptions()
	opts.Targets = req.Targets
	opts.Modules = resolveAPIModules(req.Modules, req.ModuleTags)
	opts.ProjectUUID = projectUUID

	concurrency := h.config.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}
	if req.Concurrency > 0 {
		concurrency = req.Concurrency
	}
	opts.Concurrency = concurrency

	if req.MaxPerHost > 0 {
		opts.MaxPerHost = req.MaxPerHost
	}

	if req.Timeout != "" {
		d, err := time.ParseDuration(req.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
		opts.Timeout = d
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

	// Resolve intensity to scanning profile
	if req.Intensity != "" {
		profileName, resolvedIntensity, err := agent.ResolveNativeScanIntensity(req.Intensity)
		if err != nil {
			return nil, err
		}
		opts.Intensity = resolvedIntensity
		if req.ScanningProfile == "" {
			req.ScanningProfile = profileName
		}
	}

	if req.ScanningProfile != "" {
		opts.ScanningProfile = req.ScanningProfile
	}

	return opts, nil
}

// applyStrategy resolves the scanning strategy and heuristics-check level into
// opts. Phase-isolation/skip handling is delegated to runner.ApplyNativePhaseSelection
// so the server tracks the same case list the CLI uses.
//
// strategy and heuristicsCheck are request-level overrides (empty = fall back
// to settings).
func applyStrategy(opts *types.Options, settings *config.Settings, strategy, heuristicsCheck string) error {
	strategyName := strategy
	if strategyName == "" {
		strategyName = settings.ScanningStrategy.DefaultStrategy
	}
	if strategyName != "" {
		phases, ok := settings.ScanningStrategy.GetStrategy(strategyName)
		if !ok {
			return fmt.Errorf("unknown scanning strategy %q; valid names: %v", strategyName, settings.ScanningStrategy.StrategyNames())
		}
		opts.ExternalHarvestEnabled = phases.ExternalHarvesting
		opts.DiscoverEnabled = phases.Discovery
		opts.SpideringEnabled = phases.Spidering
		opts.KnownIssueScanEnabled = phases.KnownIssueScan
		if !phases.DynamicAssessment {
			opts.SkipDynamicAssessment = true
		}
	}

	opts.HeuristicsCheck = "basic"
	if settings.ScanningStrategy.HeuristicsCheck != "" {
		opts.HeuristicsCheck = settings.ScanningStrategy.HeuristicsCheck
	}
	if heuristicsCheck != "" {
		opts.HeuristicsCheck = heuristicsCheck
	}

	return nil
}

// applyResolvedPhaseDurations resolves per-phase max durations from the scanning
// pace config (applying duration_factor to the global max_duration) and writes
// them into opts. This mirrors the CLI logic in scan.go that ensures phases like
// spidering get their factored duration (e.g. 0.15 × 2h = 18m) instead of
// falling back to their own hard-coded defaults (30m).
func applyResolvedPhaseDurations(opts *types.Options, pace *config.ScanningPaceConfig) {
	if discoveryPace := pace.ResolvePhase("discovery"); discoveryPace.MaxDuration > 0 {
		opts.DiscoverMaxDuration = discoveryPace.MaxDuration
	}
	if spideringPace := pace.ResolvePhase("spidering"); spideringPace.MaxDuration > 0 {
		opts.SpideringMaxDuration = spideringPace.MaxDuration
	}
}

// HandleRunScan handles POST /api/scans/run — triggers an async target-based scan.
// This route only accepts target URLs. Use POST /api/scan-all-records to scan DB records.
func (h *Handlers) HandleRunScan(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
		})
	}

	var req RunScanRequest
	if len(c.Body()) > 0 {
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: "invalid request body: " + err.Error(),
			})
		}
	}

	// Merge urls into targets
	if len(req.URLs) > 0 {
		req.Targets = append(req.Targets, req.URLs...)
	}

	if len(req.Targets) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "at least one target URL is required (use 'targets' or 'urls' field)",
		})
	}

	if err := validateRunScanRequest(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
		})
	}

	projectUUID := getProjectUUID(c)

	// Build runner options
	opts, err := h.buildRunScanOptions(req, projectUUID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
		})
	}

	// Clone settings and force persist_logs so API-triggered scans always
	// produce a runtime.log for `vigolium log <uuid>`.
	settings := forceNativePersistLogs(h.settings)

	// Load and apply scanning profile to settings (mirrors CLI logic in scan.go).
	// Profile-load errors are surfaced as 400s — same contract the CLI honors.
	if opts.ScanningProfile != "" {
		profilePath := settings.ScanningStrategy.ResolveProfilePath(opts.ScanningProfile)
		profile, profileErr := config.LoadProfile(profilePath)
		if profileErr != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: fmt.Sprintf("failed to load scanning profile %q: %v", opts.ScanningProfile, profileErr),
			})
		}
		if err := config.ApplyProfile(settings, profile); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: fmt.Sprintf("failed to apply scanning profile %q: %v", opts.ScanningProfile, err),
			})
		}
	}

	// Apply strategy + heuristics, then delegate only/skip to the same helper
	// the CLI uses so the case list (incl. dynamic-assessment, extension)
	// stays in sync across both entry points.
	if err := applyStrategy(opts, settings, req.Strategy, req.HeuristicsCheck); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
		})
	}
	opts.OnlyPhase = req.Only
	// Copy req.Skip — ApplyNativePhaseSelection normalizes the slice in place.
	opts.SkipPhases = append([]string(nil), req.Skip...)
	if err := runner.ApplyNativePhaseSelection(opts, func() {
		settings.DynamicAssessment.Extensions.Enabled = true
	}); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
		})
	}

	// Apply scanning_max_duration
	if req.ScanningMaxDuration != "" {
		settings.ScanningPace.MaxDuration = req.ScanningMaxDuration
	}

	// Apply rate_limit
	if req.RateLimit > 0 {
		settings.ScanningPace.RateLimit = req.RateLimit
	}

	// Resolve per-phase durations from scanning_pace (mirrors CLI behavior in scan.go)
	applyResolvedPhaseDurations(opts, &settings.ScanningPace)

	// Apply scanning_profile
	if req.ScanningProfile != "" {
		opts.ScanningProfile = req.ScanningProfile
	}

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

	formats, err := resolveAPIOutputFormats(req.OutputFormats)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{Error: err.Error()})
	}
	if len(formats) > 0 {
		// Output base path is fixed under the scan's session dir so
		// uploadNativeScanResults knows where to find the per-format files.
		opts.OutputFormats = formats
		opts.Output = filepath.Join(
			settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(),
			scanID,
			"output",
		)
	}

	ctx := context.Background()

	scanMode := "target"

	scan := &database.Scan{
		UUID:        scanID,
		ProjectUUID: projectUUID,
		Name:        "api-scan",
		Status:      "pending",
		Modules:     strings.Join(resolvedModules, ","),
		ScanSource:  "api",
		ScanMode:    scanMode,
		StartedAt:   time.Now(),
	}

	if err := h.repo.CreateScan(ctx, scan); err != nil {
		return respondScanPinError(c, err)
	}

	if req.DryRun {
		return c.Status(fiber.StatusOK).JSON(ScanResponse{
			ProjectUUID:  projectUUID,
			ScanUUID:     scanID,
			Status:       "dry_run",
			Message:      "scan record created (dry run)",
			TargetsCount: len(req.Targets),
			ScanMode:     scanMode,
		})
	}

	// Create scan runner
	scanRunner, err := runner.New(opts)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan runner: " + err.Error(),
		})
	}

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(h.repo)

	// Acquire per-project scan lock
	h.scanMu.Lock()
	st := h.getProjectScanState(projectUUID)
	if st.running {
		// Project busy — check if queuing is enabled
		if h.config.ScanQueueCapacity > 0 {
			qCh, ok := h.scanQueues[projectUUID]
			if !ok {
				qCh = make(chan *queuedScan, h.config.ScanQueueCapacity)
				h.scanQueues[projectUUID] = qCh
				go h.scanQueueWorker(projectUUID, qCh)
			}
			if len(qCh) >= h.config.ScanQueueCapacity {
				h.scanMu.Unlock()
				return c.Status(fiber.StatusTooManyRequests).JSON(ErrorResponse{
					Error: "scan queue full for this project",
				})
			}
			scan.Status = "queued"
			_ = h.repo.UpdateScan(ctx, scan)
			qCh <- &queuedScan{
				scanID:        scanID,
				runner:        scanRunner,
				projectUUID:   projectUUID,
				enqueued:      time.Now(),
				uploadResults: req.UploadResults,
			}
			h.scanMu.Unlock()
			return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
				ProjectUUID:  projectUUID,
				ScanUUID:     scanID,
				Status:       "queued",
				Message:      fmt.Sprintf("scan queued (position %d)", len(qCh)),
				TargetsCount: len(req.Targets),
				ScanMode:     scanMode,
			})
		}
		h.scanMu.Unlock()
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error: ErrScanAlreadyRunning.Error(),
		})
	}

	scan.Status = "running"
	_ = h.repo.UpdateScan(ctx, scan)

	st.runner = scanRunner
	st.running = true
	st.scanID = scanID
	h.scanMu.Unlock()

	go h.runBackgroundScan(scanID, scanRunner, projectUUID, req.UploadResults)

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID:  projectUUID,
		ScanUUID:     scanID,
		Status:       "running",
		Message:      "scan started",
		TargetsCount: len(req.Targets),
		ScanMode:     scanMode,
	})
}

// HandleListScans handles GET /api/scans — returns paginated scan history.
func (h *Handlers) HandleListScans(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
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
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to list scans: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(PaginatedResponse{
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
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	uuid := c.Params("uuid")
	if uuid == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing uuid parameter",
			Code:  fiber.StatusBadRequest,
		})
	}

	scan, err := h.repo.GetScanByUUID(c.Context(), uuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: ErrScanNotFound.Error(),
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(buildScanViews([]*database.Scan{scan})[0])
}

// HandleDeleteScan handles DELETE /api/scans/:uuid — deletes a scan record.
func (h *Handlers) HandleDeleteScan(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	scanUUID := c.Params("uuid")
	if scanUUID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing uuid parameter",
			Code:  fiber.StatusBadRequest,
		})
	}

	// Verify scan exists
	_, err := h.repo.GetScanByUUID(c.Context(), scanUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: ErrScanNotFound.Error(),
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	if err := h.repo.DeleteScan(c.Context(), scanUUID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to delete scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
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
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing uuid parameter",
			Code:  fiber.StatusBadRequest,
		})
	}

	h.scanMu.Lock()
	defer h.scanMu.Unlock()

	// Find the scan across all projects
	for _, st := range h.scanStates {
		if st.running && st.scanID == scanUUID {
			if st.runner != nil {
				st.runner.Close()
			}
			return c.JSON(ScanStatusResponse{
				ProjectUUID: getProjectUUID(c),
				ScanUUID:    scanUUID,
				Running:     true,
				Status:      "cancelling",
				Message:     "scan stop requested, workers finishing current tasks",
			})
		}
	}

	return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
		Error: "scan " + scanUUID + " is not running",
		Code:  fiber.StatusConflict,
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
	var paused bool
	if st != nil && st.running {
		running = true
		scanID = st.scanID
		paused = st.runner != nil && st.runner.IsPaused()
	}
	h.scanMu.Unlock()

	if running {
		status := "running"
		if paused {
			status = "paused"
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
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing uuid parameter",
			Code:  fiber.StatusBadRequest,
		})
	}

	h.scanMu.Lock()
	defer h.scanMu.Unlock()

	// Find the scan across all projects
	for _, st := range h.scanStates {
		if st.running && st.scanID == scanUUID {
			if st.runner.IsPaused() {
				return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
					Error: "scan is already paused",
					Code:  fiber.StatusConflict,
				})
			}
			st.runner.Pause()
			if h.repo != nil {
				_ = h.repo.PauseScan(c.Context(), scanUUID)
			}
			return c.JSON(ScanStatusResponse{
				ProjectUUID: getProjectUUID(c),
				ScanUUID:    scanUUID,
				Running:     true,
				Status:      "paused",
				Message:     "scan paused, workers finishing current items",
			})
		}
	}

	return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
		Error: "scan " + scanUUID + " is not running",
		Code:  fiber.StatusConflict,
	})
}

// HandleResumeScan handles POST /api/scans/:uuid/resume — resumes a paused scan.
func (h *Handlers) HandleResumeScan(c fiber.Ctx) error {
	scanUUID := c.Params("uuid")
	if scanUUID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing uuid parameter",
			Code:  fiber.StatusBadRequest,
		})
	}

	h.scanMu.Lock()
	defer h.scanMu.Unlock()

	// Find the scan across all projects
	for _, st := range h.scanStates {
		if st.running && st.scanID == scanUUID {
			if !st.runner.IsPaused() {
				return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
					Error: "scan is not paused",
					Code:  fiber.StatusConflict,
				})
			}
			st.runner.Resume()
			if h.repo != nil {
				_ = h.repo.ResumeScan(c.Context(), scanUUID)
			}
			return c.JSON(ScanStatusResponse{
				ProjectUUID: getProjectUUID(c),
				ScanUUID:    scanUUID,
				Running:     true,
				Status:      "running",
				Message:     "scan resumed",
			})
		}
	}

	return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
		Error: "scan " + scanUUID + " is not running",
		Code:  fiber.StatusConflict,
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
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	scanUUID := c.Params("uuid")
	if scanUUID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing uuid parameter",
			Code:  fiber.StatusBadRequest,
		})
	}

	// Verify scan exists
	_, err := h.repo.GetScanByUUID(c.Context(), scanUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
				Error: ErrScanNotFound.Error(),
				Code:  fiber.StatusNotFound,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	// Prefer the on-disk runtime.log — that's what /api/scan-request and
	// /api/scan-url produce today, and it matches what the CLI `vigolium log`
	// command streams.
	sessionsDir := config.ExpandPath("~/.vigolium/native-sessions/")
	if h.settings != nil {
		sessionsDir = h.settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir()
	}
	if logPath := resolveRuntimeLogPath(filepath.Join(sessionsDir, scanUUID)); logPath != "" {
		data, readErr := os.ReadFile(logPath)
		if readErr != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Error: "failed to read runtime.log: " + readErr.Error(),
				Code:  fiber.StatusInternalServerError,
			})
		}
		if parseBoolParam(c.Query("strip")) {
			data = []byte(stripANSI(string(data)))
		}
		c.Set("Content-Type", "text/plain; charset=utf-8")
		return c.Send(data)
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
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to retrieve scan logs: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(fiber.Map{
		"project_uuid": getProjectUUID(c),
		"logs":         logs,
		"total":        total,
	})
}

// runBackgroundScan runs the scan in a background goroutine. When
// uploadResults is true and storage is configured, the scan's runtime.log
// (and any output files) are bundled and uploaded to
// <projectUUID>/native-scans/<scanID>/results.tar.gz after the scan completes.
func (h *Handlers) runBackgroundScan(scanID string, scanRunner *runner.Runner, projectUUID string, uploadResults bool) {
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

	ctx := context.Background()
	if err := h.repo.CompleteScan(ctx, scanID, errMsg); err != nil {
		zap.L().Error("Failed to complete scan record", zap.String("scan_uuid", scanID), zap.Error(err))
	}

	if uploadResults {
		h.uploadNativeScanResults(projectUUID, scanID)
	}

	webhook.FireNativeScan(h.settings, h.repo, scanID)
}
