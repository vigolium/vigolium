package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// HandleScanURL handles POST /api/scan-url — scans a single URL asynchronously.
func (h *Handlers) HandleScanURL(c fiber.Ctx) error {
	var req ScanURLRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
		})
	}

	if req.URL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingURL.Error(),
		})
	}

	// Validate URL
	if _, err := url.ParseRequestURI(req.URL); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid URL: " + err.Error(),
		})
	}

	// Default method to GET
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}

	// Build raw HTTP request from URL/method/body/headers
	rr, err := buildRequestFromParams(req.URL, method, req.Body, req.Headers)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to build request: " + err.Error(),
		})
	}

	// Parse module IDs
	var moduleIDs []string
	if req.Modules != "" {
		for _, m := range strings.Split(req.Modules, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				moduleIDs = append(moduleIDs, m)
			}
		}
	}

	scanID := uuid.New().String()

	projectUUID := getProjectUUID(c)

	// Create scan record if database is available
	if h.repo != nil {
		ctx := context.Background()
		scan := &database.Scan{
			UUID:        scanID,
			ProjectUUID: projectUUID,
			Name:        "scan-url",
			Status:      "running",
			Target:      req.URL,
			Modules:     req.Modules,
			ScanSource:  "api",
			ScanMode:    "single",
			StartedAt:   time.Now(),
		}
		if err := h.repo.CreateScan(ctx, scan); err != nil {
			zap.L().Warn("Failed to create scan record", zap.Error(err))
		}
	}

	go h.runBackgroundURLScan(scanID, rr, moduleIDs, req.NoPassive)

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID: projectUUID,
		ScanID:      scanID,
		Status:      "running",
		Message:     fmt.Sprintf("scan-url started for %s", req.URL),
	})
}

// HandleScanRequest handles POST /api/scan-request — scans a raw HTTP request asynchronously.
func (h *Handlers) HandleScanRequest(c fiber.Ctx) error {
	var req ScanRequestRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
		})
	}

	if req.RawRequest == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingRawRequest.Error(),
		})
	}

	// Base64-decode the raw request
	rawBytes, err := base64.StdEncoding.DecodeString(req.RawRequest)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to decode raw_request: " + err.Error(),
		})
	}

	rawStr := strings.TrimSpace(string(rawBytes))
	if rawStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingRawRequest.Error(),
		})
	}

	// Parse raw HTTP request
	var rr *httpmsg.HttpRequestResponse
	if req.TargetURL != "" {
		rr, err = httpmsg.ParseRawRequestWithURL(rawStr, req.TargetURL)
	} else {
		rr, err = httpmsg.ParseRawRequest(rawStr)
	}
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrInvalidRawRequest.Error() + ": " + err.Error(),
		})
	}

	// Parse module IDs
	var moduleIDs []string
	if req.Modules != "" {
		for _, m := range strings.Split(req.Modules, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				moduleIDs = append(moduleIDs, m)
			}
		}
	}

	scanID := uuid.New().String()
	target := rr.Target()
	projectUUID := getProjectUUID(c)

	// Create scan record if database is available
	if h.repo != nil {
		ctx := context.Background()
		scan := &database.Scan{
			UUID:        scanID,
			ProjectUUID: projectUUID,
			Name:        "scan-request",
			Status:      "running",
			Target:      target,
			Modules:     req.Modules,
			ScanSource:  "api",
			ScanMode:    "single",
			StartedAt:   time.Now(),
		}
		if err := h.repo.CreateScan(ctx, scan); err != nil {
			zap.L().Warn("Failed to create scan record", zap.Error(err))
		}
	}

	go h.runBackgroundURLScan(scanID, rr, moduleIDs, req.NoPassive)

	return c.Status(fiber.StatusAccepted).JSON(ScanResponse{
		ProjectUUID: projectUUID,
		ScanID:      scanID,
		Status:      "running",
		Message:     fmt.Sprintf("scan-request started for %s", target),
	})
}

// buildRequestFromParams constructs an HttpRequestResponse from URL, method, body, and headers.
// This mirrors the CLI buildRequestFromFlags but takes a map of headers instead of a slice.
func buildRequestFromParams(target, method, body string, headers map[string]string) (*httpmsg.HttpRequestResponse, error) {
	method = strings.ToUpper(method)

	// Simple case: GET with no body or custom headers
	if method == "GET" && body == "" && len(headers) == 0 {
		return httpmsg.GetRawRequestFromURL(target)
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	path := u.RequestURI()
	host := u.Host

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&sb, "Host: %s\r\n", host)

	for k, v := range headers {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}

	if body != "" {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}

	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	return httpmsg.ParseRawRequestWithURL(sb.String(), target)
}

// runBackgroundURLScan runs a single-URL scan in a background goroutine.
func (h *Handlers) runBackgroundURLScan(scanID string, rr *httpmsg.HttpRequestResponse, moduleIDs []string, noPassive bool) {
	start := time.Now()
	zap.L().Info("Background URL scan started",
		zap.String("scan_id", scanID),
		zap.String("target", rr.Target()))

	// Get filtered modules
	active, passive := getFilteredModulesServer(moduleIDs, noPassive)

	// Create single-item source
	src := source.NewSingleSource(rr, moduleIDs)

	// Collect findings
	var mu sync.Mutex
	var findings []*output.ResultEvent

	concurrency := h.config.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	executorCfg := core.ExecutorConfig{
		Workers:              concurrency,
		HTTPRequester:        h.httpRequester,
		Repository:           h.repo,
		ScanUUID:             scanID,
		MaxFindingsPerModule: 10,
		OnResult: func(result *output.ResultEvent) {
			mu.Lock()
			findings = append(findings, result)
			mu.Unlock()
		},
	}

	executor := core.NewExecutor(executorCfg, src, active, passive)

	ctx := context.Background()
	var errMsg string
	if _, execErr := executor.Execute(ctx); execErr != nil {
		errMsg = execErr.Error()
		zap.L().Error("Background URL scan failed",
			zap.String("scan_id", scanID), zap.Error(execErr))
	}

	elapsed := time.Since(start)
	zap.L().Info("Background URL scan completed",
		zap.String("scan_id", scanID),
		zap.Int("findings", len(findings)),
		zap.Duration("elapsed", elapsed))

	// Complete scan record
	if h.repo != nil {
		if err := h.repo.CompleteScan(context.Background(), scanID, errMsg); err != nil {
			zap.L().Error("Failed to complete scan record",
				zap.String("scan_id", scanID), zap.Error(err))
		}
	}
}

// getFilteredModulesServer returns active and passive modules based on module IDs and noPassive flag.
func getFilteredModulesServer(moduleIDs []string, noPassive bool) ([]modules.ActiveModule, []modules.PassiveModule) {
	var active []modules.ActiveModule
	var passive []modules.PassiveModule

	// Resolve fuzzy patterns to exact IDs
	resolved := modules.ResolveModulePatterns(moduleIDs)
	isAll := len(resolved) == 0 || (len(resolved) == 1 && resolved[0] == "all")

	if !isAll {
		active = modules.GetActiveModulesByIDs(resolved)
		if !noPassive {
			passive = modules.GetPassiveModulesByIDs(resolved)
		}
	} else {
		active = modules.GetActiveModules()
		if !noPassive {
			passive = modules.GetPassiveModules()
		}
	}

	return active, passive
}
