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
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// normalizePhase maps phase aliases to their canonical names.
func normalizePhase(phase string) string {
	switch phase {
	case "deparos", "discover":
		return "discovery"
	case "spitolas":
		return "spidering"
	case "dynamic-assessment":
		return "audit"
	case "ext":
		return "extension"
	default:
		return phase
	}
}

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
	"spidering": {}, "spa": {}, "audit": {},
	"sast": {}, "extension": {},
}

// validateRunScanRequest validates the RunScanRequest fields.
func validateRunScanRequest(req RunScanRequest) error {
	if req.Strategy != "" {
		switch req.Strategy {
		case "lite", "balanced", "deep", "whitebox":
		default:
			return fmt.Errorf("invalid strategy %q; valid values: lite, balanced, deep, whitebox", req.Strategy)
		}
	}

	if req.Only != "" {
		normalized := normalizePhase(req.Only)
		if _, ok := validPhases[normalized]; !ok {
			return fmt.Errorf("invalid only %q; valid phases: ingestion, discovery (deparos), spidering (spitolas), external-harvest, spa, sast, audit, extension (ext)", req.Only)
		}
	}

	if req.Only != "" && len(req.Skip) > 0 {
		return fmt.Errorf("only and skip are mutually exclusive; use one or the other")
	}

	if len(req.Skip) > 0 {
		for _, phase := range req.Skip {
			normalized := normalizePhase(phase)
			switch normalized {
			case "discovery", "ingestion", "external-harvest", "spidering", "spa", "sast", "audit":
			default:
				return fmt.Errorf("invalid skip value %q; valid phases: discovery (deparos), external-harvest, spidering (spitolas), spa, sast, audit", phase)
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

	// SAST repo field validation
	if req.RepoPath != "" && req.RepoURL != "" {
		return ErrRepoPathURLExclusive
	}
	if req.RepoPath != "" {
		if !filepath.IsAbs(req.RepoPath) {
			return fmt.Errorf("repo_path must be an absolute path")
		}
		info, err := os.Stat(req.RepoPath)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("repo_path %q does not exist or is not a directory", req.RepoPath)
		}
	}
	if req.RepoURL != "" {
		if !strings.HasPrefix(req.RepoURL, "https://") && !strings.HasPrefix(req.RepoURL, "http://") &&
			!strings.HasPrefix(req.RepoURL, "git://") && !strings.HasPrefix(req.RepoURL, "git@") {
			return fmt.Errorf("repo_url must start with https://, http://, git://, or git@")
		}
	}

	return nil
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

	if req.ScanningProfile != "" {
		opts.ScanningProfile = req.ScanningProfile
	}

	// Wire SAST ad-hoc field
	if req.RepoPath != "" {
		opts.SASTAdhoc = req.RepoPath
		opts.SASTEnabled = true
	}
	if req.RepoURL != "" {
		opts.SASTAdhoc = req.RepoURL
		opts.SASTEnabled = true
	}

	return opts, nil
}

// applyStrategyAndPhases applies strategy, --only, --skip, and heuristics to opts.
func applyStrategyAndPhases(opts *types.Options, settings *config.Settings, req RunScanRequest) error {
	// Apply scanning strategy as baseline
	strategyName := req.Strategy
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
		opts.SPAEnabled = phases.SPA
		if phases.SourceAware {
			opts.SASTEnabled = true
		}
		if !phases.Audit {
			opts.SkipAudit = true
		}
	}

	// Resolve heuristics check level
	opts.HeuristicsCheck = "basic"
	if settings.ScanningStrategy.HeuristicsCheck != "" {
		opts.HeuristicsCheck = settings.ScanningStrategy.HeuristicsCheck
	}
	if req.HeuristicsCheck != "" {
		opts.HeuristicsCheck = req.HeuristicsCheck
	}

	// Normalize and apply --only
	only := normalizePhase(req.Only)
	if only != "" {
		switch only {
		case "ingestion":
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.SPAEnabled = false
			opts.SkipAudit = true
		case "discovery":
			opts.DiscoverEnabled = true
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.SPAEnabled = false
			opts.SkipAudit = true
		case "external-harvest":
			opts.ExternalHarvestEnabled = true
			opts.DiscoverEnabled = false
			opts.SpideringEnabled = false
			opts.SPAEnabled = false
			opts.SkipIngestion = true
			opts.SkipAudit = true
		case "spidering":
			opts.SpideringEnabled = true
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SPAEnabled = false
			opts.SkipIngestion = true
			opts.SkipAudit = true
		case "spa":
			opts.SPAEnabled = true
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.SkipIngestion = true
			opts.SkipAudit = true
		case "audit":
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.SPAEnabled = false
			opts.SkipIngestion = true
			opts.SkipAudit = false
		case "sast":
			opts.SASTEnabled = true
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.SPAEnabled = false
			opts.SkipIngestion = true
			opts.SkipAudit = true
		case "extension":
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.SPAEnabled = false
			opts.SkipIngestion = true
			opts.SkipAudit = false
			opts.ExtensionsOnly = true
		}
		opts.HeuristicsCheck = "none"
	}

	// Apply --skip phases
	for _, phase := range req.Skip {
		phase = normalizePhase(phase)
		switch phase {
		case "discovery", "ingestion":
			opts.SkipIngestion = true
		case "external-harvest":
			opts.ExternalHarvestEnabled = false
		case "spidering":
			opts.SpideringEnabled = false
		case "spa":
			opts.SPAEnabled = false
		case "sast":
			opts.SASTEnabled = false
		case "audit":
			opts.SkipAudit = true
		}
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

	// Targets are optional when repo_path or repo_url is provided (SAST-only scan)
	hasSASTRepo := req.RepoPath != "" || req.RepoURL != ""
	if len(req.Targets) == 0 && !hasSASTRepo {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "at least one target URL is required (use 'targets' or 'urls' field), or provide 'repo_path'/'repo_url' for SAST scan",
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

	// Clone settings
	var settings *config.Settings
	if h.settings != nil {
		clone := *h.settings
		settings = &clone
	} else {
		settings = config.DefaultSettings()
	}

	// Clone repo_url if provided (mirrors CLI logic in pkg/cli/source_add.go)
	if req.RepoURL != "" {
		clonedPath, cloneErr := cloneRepoForAPI(req.RepoURL, settings)
		if cloneErr != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: "failed to clone repo_url: " + cloneErr.Error(),
			})
		}
		opts.SASTAdhoc = clonedPath
	}

	// Auto-set only=sast when a repo is provided but no phase is specified
	if hasSASTRepo && req.Only == "" && len(req.Skip) == 0 && len(req.Targets) == 0 {
		req.Only = "sast"
	}

	// Apply strategy and phases
	if err := applyStrategyAndPhases(opts, settings, req); err != nil {
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
	scanID := uuid.New().String()
	ctx := context.Background()

	scanMode := "target"
	if opts.SASTAdhoc != "" {
		scanMode = "sast"
	}

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
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan: " + err.Error(),
		})
	}

	if req.DryRun {
		return c.Status(fiber.StatusOK).JSON(ScanResponse{
			ProjectUUID:  projectUUID,
			ScanID:       scanID,
			Status:       "dry_run",
			Message:      "scan record created (dry run)",
			TargetsCount: len(req.Targets),
			ScanMode:     scanMode,
			RepoPath:     opts.SASTAdhoc,
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
				scanID:      scanID,
				runner:      scanRunner,
				projectUUID: projectUUID,
				enqueued:    time.Now(),
			}
			h.scanMu.Unlock()
			return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
				ProjectUUID:  projectUUID,
				ScanID:       scanID,
				Status:       "queued",
				Message:      fmt.Sprintf("scan queued (position %d)", len(qCh)),
				TargetsCount: len(req.Targets),
				ScanMode:     scanMode,
				RepoPath:     opts.SASTAdhoc,
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

	go h.runBackgroundScan(scanID, scanRunner, projectUUID)

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID:  projectUUID,
		ScanID:       scanID,
		Status:       "running",
		Message:      "scan started",
		TargetsCount: len(req.Targets),
		ScanMode:     scanMode,
		RepoPath:     opts.SASTAdhoc,
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
		Data:        scans,
		Total:       total,
		Limit:       limit,
		Offset:      offset,
		HasMore:     int64(offset+limit) < total,
	})
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

	return c.JSON(scan)
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
				ScanID:      scanUUID,
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
			ScanID:      scanID,
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

// HandleCancelScan handles DELETE /api/scan — cancels a running scan for the current project.
func (h *Handlers) HandleCancelScan(c fiber.Ctx) error {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()

	projectUUID := getProjectUUID(c)
	st := h.scanStates[projectUUID]

	if st == nil || !st.running {
		return c.JSON(ScanStatusResponse{
			ProjectUUID: projectUUID,
			Running:     false,
			Status:      "idle",
			Message:     "no scan is running for this project",
		})
	}

	// Close the runner — stops the input source, workers finish current tasks
	if st.runner != nil {
		st.runner.Close()
	}

	return c.JSON(ScanStatusResponse{
		ProjectUUID: projectUUID,
		ScanID:      st.scanID,
		Running:     true,
		Status:      "cancelling",
		Message:     "scan cancellation requested, workers finishing current tasks",
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
				ScanID:      scanUUID,
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
				ScanID:      scanUUID,
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

// HandleGetScanLogs handles GET /api/scans/:uuid/logs — returns scan log entries.
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

// runBackgroundScan runs the scan in a background goroutine.
func (h *Handlers) runBackgroundScan(scanID string, scanRunner *runner.Runner, projectUUID string) {
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
	zap.L().Info("Background scan started", zap.String("scan_id", scanID))

	var errMsg string
	if err := scanRunner.RunNativeScan(); err != nil {
		errMsg = err.Error()
		zap.L().Error("Background scan failed", zap.String("scan_id", scanID), zap.Error(err))
	}

	scanRunner.Close()

	elapsed := time.Since(start)
	zap.L().Info("Background scan completed",
		zap.String("scan_id", scanID),
		zap.Duration("elapsed", elapsed))

	ctx := context.Background()
	if err := h.repo.CompleteScan(ctx, scanID, errMsg); err != nil {
		zap.L().Error("Failed to complete scan record", zap.String("scan_id", scanID), zap.Error(err))
	}
}
