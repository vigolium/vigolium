package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// HandleScanRecords handles POST /api/scan-records — starts a scan on specific HTTP records by UUID.
func (h *Handlers) HandleScanRecords(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	var req ScanRecordsRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	if len(req.RecordUUIDs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingRecordUUIDs.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Validate UUIDs exist in DB
	records, err := h.repo.GetRecordsByUUIDs(c.Context(), req.RecordUUIDs)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to validate record UUIDs: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}
	if len(records) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrNoValidRecords.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Collect validated UUIDs
	validUUIDs := make([]string, len(records))
	for i, r := range records {
		validUUIDs[i] = r.UUID
	}

	ctx := context.Background()
	projectUUID := getProjectUUID(c)

	modules := []string{"all"}
	if len(req.EnableModules) > 0 {
		modules = req.EnableModules
	}

	// Create scan record
	scanID := uuid.New().String()
	scan := &database.Scan{
		UUID:        scanID,
		ProjectUUID: projectUUID,
		Name:        "selective-scan",
		Status:      "pending",
		Modules:     strings.Join(modules, ","),
		ScanSource:  "api",
		ScanMode:    "selective",
		StartedAt:   time.Now(),
	}
	if err := h.repo.CreateScan(ctx, scan); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan: " + err.Error(),
		})
	}

	// Build runner options
	opts := types.DefaultOptions()
	concurrency := h.config.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}
	opts.Concurrency = concurrency
	opts.Modules = modules

	// Create UUID list input source
	dbSource := database.NewUUIDListDBInputSource(h.repo, validUUIDs)

	scanRunner, err := runner.NewWithInputSource(opts, dbSource)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan runner: " + err.Error(),
		})
	}

	scanRunner.SetSettings(h.settings)
	scanRunner.SetRepository(h.repo)

	// Acquire per-project scan lock
	h.scanMu.Lock()
	st := h.getProjectScanState(projectUUID)
	if st.running {
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

	// Launch background scan
	go h.runBackgroundScan(scanID, scanRunner, projectUUID)

	zap.L().Info("Selective scan started",
		zap.String("scan_id", scanID),
		zap.Int("record_count", len(validUUIDs)))

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID:   projectUUID,
		ScanID:        scanID,
		Status:        "running",
		Message:       "selective scan started",
		RecordsToScan: int64(len(validUUIDs)),
	})
}

// validateScanAllRecordsRequest validates the ScanAllRecordsRequest fields.
func validateScanAllRecordsRequest(req ScanAllRecordsRequest) error {
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
	if req.HeuristicsCheck != "" {
		switch req.HeuristicsCheck {
		case "none", "basic", "advanced":
		default:
			return fmt.Errorf("invalid heuristics_check %q; valid values: none, basic, advanced", req.HeuristicsCheck)
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

// HandleScanAllRecords handles POST /api/scan-all-records — scans existing HTTP records
// from the database with optional filtering by hostname, method, path, status code, etc.
func (h *Handlers) HandleScanAllRecords(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	// Parse request body (allow empty body → scan all records)
	var req ScanAllRecordsRequest
	if len(c.Body()) > 0 {
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: "invalid request body: " + err.Error(),
				Code:  fiber.StatusBadRequest,
			})
		}
	}

	if err := validateScanAllRecordsRequest(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	projectUUID := getProjectUUID(c)

	// Build query filters from request
	filters := database.QueryFilters{
		ProjectUUID:  projectUUID,
		HostPattern:  req.Hostname,
		Methods:      req.Methods,
		PathPattern:  req.Path,
		StatusCodes:  req.StatusCodes,
		Source:       req.Source,
		SearchTerm:   req.Search,
		MinRiskScore: req.MinRiskScore,
		Remark:       req.Remark,
	}

	// Query matching record UUIDs
	qb := database.NewQueryBuilder(h.db, filters)
	query := qb.BuildRecordsQuery().Column("r.uuid")
	ctx := c.Context()

	var matchingUUIDs []string
	if err := query.Scan(ctx, &matchingUUIDs); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to query records: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	if len(matchingUUIDs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "no records match the specified filters",
			Code:  fiber.StatusBadRequest,
		})
	}

	// Resolve modules
	modules := resolveAPIModules(req.Modules, req.ModuleTags)

	// Build runner options
	opts := types.DefaultOptions()
	opts.Modules = modules
	opts.ProjectUUID = projectUUID
	opts.SkipIngestion = true
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SpideringEnabled = false
	opts.KnownIssueScanEnabled = false
	opts.SkipAudit = false

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
		d, _ := time.ParseDuration(req.Timeout) // already validated
		opts.Timeout = d
	}

	if len(req.Headers) > 0 {
		headers := make([]string, 0, len(req.Headers))
		for k, v := range req.Headers {
			headers = append(headers, k+": "+v)
		}
		opts.Headers = headers
	}

	// Resolve intensity to scanning profile
	if req.Intensity != "" {
		if profileName, resolvedIntensity, err := agent.ResolveNativeScanIntensity(req.Intensity); err == nil {
			opts.Intensity = resolvedIntensity
			if req.ScanningProfile == "" {
				req.ScanningProfile = profileName
			}
		}
	}

	if req.ScanningProfile != "" {
		opts.ScanningProfile = req.ScanningProfile
	}

	// Clone settings
	var settings *config.Settings
	if h.settings != nil {
		clone := *h.settings
		settings = &clone
	} else {
		settings = config.DefaultSettings()
	}

	// Load and apply scanning profile to settings
	if opts.ScanningProfile != "" {
		profilePath := settings.ScanningStrategy.ResolveProfilePath(opts.ScanningProfile)
		if profile, profileErr := config.LoadProfile(profilePath); profileErr == nil {
			_ = config.ApplyProfile(settings, profile)
		}
	}

	if req.HeuristicsCheck != "" {
		opts.HeuristicsCheck = req.HeuristicsCheck
	}
	if req.ScanningMaxDuration != "" {
		settings.ScanningPace.MaxDuration = req.ScanningMaxDuration
	}
	if req.RateLimit > 0 {
		settings.ScanningPace.RateLimit = req.RateLimit
	}

	// Resolve per-phase durations from scanning_pace (mirrors CLI behavior in scan.go)
	applyResolvedPhaseDurations(opts, &settings.ScanningPace)

	scanMode := "full"
	if !req.Force {
		scanMode = "incremental"
	}

	scanID := uuid.New().String()
	bgCtx := context.Background()

	scan := &database.Scan{
		UUID:        scanID,
		ProjectUUID: projectUUID,
		Name:        "all-records-scan",
		Status:      "pending",
		Modules:     strings.Join(modules, ","),
		ScanSource:  "api",
		ScanMode:    scanMode,
		StartedAt:   time.Now(),
	}

	if err := h.repo.CreateScan(bgCtx, scan); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	if req.DryRun {
		scan.Status = "dry_run"
		_ = h.repo.UpdateScan(bgCtx, scan)
		return c.Status(fiber.StatusOK).JSON(ScanResponse{
			ProjectUUID:   projectUUID,
			ScanID:        scanID,
			Status:        "dry_run",
			Message:       "scan record created (dry run)",
			RecordsToScan: int64(len(matchingUUIDs)),
			ScanMode:      scanMode,
		})
	}

	// Create UUID list input source from filtered records
	dbSource := database.NewUUIDListDBInputSource(h.repo, matchingUUIDs)

	scanRunner, err := runner.NewWithInputSource(opts, dbSource)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create scan runner: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(h.repo)

	// Acquire per-project scan lock
	h.scanMu.Lock()
	st := h.getProjectScanState(projectUUID)
	if st.running {
		h.scanMu.Unlock()
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error: ErrScanAlreadyRunning.Error(),
		})
	}

	scan.Status = "running"
	_ = h.repo.UpdateScan(bgCtx, scan)

	st.runner = scanRunner
	st.running = true
	st.scanID = scanID
	h.scanMu.Unlock()

	go h.runBackgroundScan(scanID, scanRunner, projectUUID)

	zap.L().Info("All-records scan started",
		zap.String("scan_id", scanID),
		zap.Int("record_count", len(matchingUUIDs)),
		zap.String("scan_mode", scanMode))

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID:   projectUUID,
		ScanID:        scanID,
		Status:        "running",
		Message:       "all-records scan started",
		RecordsToScan: int64(len(matchingUUIDs)),
		ScanMode:      scanMode,
	})
}
