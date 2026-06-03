//go:build e2e || canary

package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	dockercontainer "github.com/moby/moby/api/types/container"
	dockernetwork "github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestInfra holds the test infrastructure components
type TestInfra struct {
	HTTPClient  *httpRequester.Requester
	HostErrors  *hosterrors.Cache
	HostLimiter *hostlimit.HostRateLimiter
	Options     *types.Options
	ScanCtx     *modkit.ScanContext
}

// SetupTestInfra initializes HTTP client and services for e2e tests
func SetupTestInfra() (*TestInfra, error) {
	opts := types.DefaultOptions()
	opts.Timeout = 30
	opts.Retries = 2
	opts.MaxHostError = 10
	opts.MaxPerHost = 5

	if err := network.Init(opts); err != nil {
		return nil, fmt.Errorf("failed to initialize network: %w", err)
	}

	hostErrors := hosterrors.New(opts.MaxHostError, hosterrors.DefaultMaxHostsCount, nil)
	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost: opts.MaxPerHost,
	})

	svc := &services.Services{
		Options:     opts,
		HostLimiter: hostLimiter,
		HostErrors:  hostErrors,
	}

	httpClient, err := httpRequester.NewRequester(opts, svc)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP requester: %w", err)
	}

	// ScanContext can be nil for tests (dedup not needed)
	scanCtx := &modkit.ScanContext{
		DedupManager: nil,
	}

	return &TestInfra{
		HTTPClient:  httpClient,
		HostErrors:  hostErrors,
		HostLimiter: hostLimiter,
		Options:     opts,
		ScanCtx:     scanCtx,
	}, nil
}

// Cleanup performs cleanup after tests.
// Does NOT close the global network dialer — it may be shared with scan runners
// that call network.Close() themselves. The dialer now nils itself on Close(),
// so Init() will re-create it if needed by a subsequent test.
func (infra *TestInfra) Cleanup() {
	if infra.HostErrors != nil {
		infra.HostErrors.Close()
	}
	if infra.HostLimiter != nil {
		_ = infra.HostLimiter.Close()
	}
	// NOTE: Intentionally NOT calling network.Close() here.
	// The runner.Close() already calls it, and closing a second time
	// from a different test would destroy the dialer for concurrent tests.
	// Since network.Close() now nils the Dialer, Init() will re-create it.
}

// reservedPorts must never be allocated to e2e tests. The local UI dashboard
// runs on 5002 (cloud/console) and 3002 (workbench/static), so binding either
// would clash with a developer's running console.
var reservedPorts = map[int]bool{5002: true, 3002: true}

// pickFreeHostPort asks the kernel for a free TCP port that isn't on the
// reservedPorts list. Used by both the in-process API server (getFreePort)
// and StartContainer's host-side port pinning so Docker can never publish
// onto the local UI's port.
func pickFreeHostPort() (int, error) {
	for i := 0; i < 16; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, fmt.Errorf("listen: %w", err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		if !reservedPorts[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("kernel kept handing out reserved UI ports (%v)", reservedPorts)
}

// getFreePort is the *testing.T-flavored wrapper around pickFreeHostPort.
func getFreePort(t *testing.T) int {
	t.Helper()
	port, err := pickFreeHostPort()
	if err != nil {
		t.Fatalf("getFreePort: %v", err)
	}
	return port
}

// ContainerConfig holds configuration for starting a vulnerable app container
type ContainerConfig struct {
	Image         string
	ExposedPort   string
	WaitStrategy  wait.Strategy
	Env           map[string]string
	ReadyEndpoint string
}

// VulnerableApp represents a running vulnerable application container
type VulnerableApp struct {
	Container testcontainers.Container
	BaseURL   string
	ctx       context.Context
}

// StartContainer starts a Docker container with the given configuration.
// The host-side port is pre-picked from a reservation-aware pool so the
// daemon never publishes onto the local UI's port (5002, 3002).
func StartContainer(ctx context.Context, config ContainerConfig) (*VulnerableApp, error) {
	// Strip /tcp suffix if present to get the bare container port number.
	port := config.ExposedPort
	if len(port) > 4 && port[len(port)-4:] == "/tcp" {
		port = port[:len(port)-4]
	}

	hostPort, err := pickFreeHostPort()
	if err != nil {
		return nil, fmt.Errorf("failed to pick host port for %s: %w", config.Image, err)
	}

	// testcontainers v0.42 parses each ExposedPorts entry with
	// network.ParsePortRange, which only accepts a bare port/range ("80/tcp") —
	// the old "host_ip:host_port:container_port/proto" spec is rejected. Host-side
	// port pinning now lives in HostConfigModifier via PortBindings. Pinning
	// HostIP to 127.0.0.1 keeps the test container off the LAN, and the
	// pre-picked hostPort avoids the reserved local-UI ports (5002, 3002).
	containerPort := port + "/tcp"
	natPort, err := dockernetwork.ParsePort(containerPort)
	if err != nil {
		return nil, fmt.Errorf("parse container port %q for %s: %w", containerPort, config.Image, err)
	}

	req := testcontainers.ContainerRequest{
		Image:        config.Image,
		ExposedPorts: []string{containerPort},
		WaitingFor:   config.WaitStrategy,
		Env:          config.Env,
		HostConfigModifier: func(hc *dockercontainer.HostConfig) {
			hc.PortBindings = dockernetwork.PortMap{
				natPort: []dockernetwork.PortBinding{{
					HostIP:   netip.MustParseAddr("127.0.0.1"),
					HostPort: strconv.Itoa(hostPort),
				}},
			}
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start container %s: %w", config.Image, err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	mappedPort, err := container.MappedPort(ctx, port)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get mapped port: %w", err)
	}

	baseURL := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	// Wait for the app to be ready
	if config.ReadyEndpoint != "" {
		if err := waitForEndpoint(baseURL+config.ReadyEndpoint, 60*time.Second); err != nil {
			_ = container.Terminate(ctx)
			return nil, fmt.Errorf("app not ready: %w", err)
		}
	}

	return &VulnerableApp{
		Container: container,
		BaseURL:   baseURL,
		ctx:       ctx,
	}, nil
}

// Stop terminates the container
func (app *VulnerableApp) Stop() error {
	if app.Container != nil {
		return app.Container.Terminate(app.ctx)
	}
	return nil
}

// runActiveScan dispatches an ActiveModule's scan method based on its declared
// ScanScopes, mirroring the runtime Executor. Use this in canary/e2e tests
// instead of calling ScanPerRequest directly — the base module's default
// implementations panic when the declared scope doesn't match, which is a
// footgun for tests that pick modules ad-hoc.
func runActiveScan(t *testing.T, mod modules.ActiveModule, rr *httpmsg.HttpRequestResponse, infra *TestInfra) ([]*output.ResultEvent, error) {
	t.Helper()

	scopes := mod.ScanScopes()

	switch {
	case scopes.Has(modkit.ScanScopeInsertionPoint):
		points, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
		if err != nil {
			return nil, fmt.Errorf("create insertion points: %w", err)
		}
		allowed := mod.AllowedInsertionPointTypes()
		var all []*output.ResultEvent
		for _, ip := range points {
			if !allowed.Contains(ip.Type()) {
				continue
			}
			findings, err := mod.ScanPerInsertionPoint(rr, ip, infra.HTTPClient, infra.ScanCtx)
			if err != nil {
				return all, err
			}
			all = append(all, findings...)
		}
		return all, nil

	case scopes.Has(modkit.ScanScopeRequest):
		return mod.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)

	case scopes.Has(modkit.ScanScopeHost):
		return mod.ScanPerHost(rr, infra.HTTPClient, infra.ScanCtx)

	default:
		return nil, fmt.Errorf("module %q has no recognized ScanScope (%v)", mod.ID(), scopes)
	}
}

// seedVAmPIDatabase populates VAmPI's SQLite tables via its /createdb endpoint.
// A freshly started VAmPI container has no tables, so every query — including
// the scanner's baseline request — returns a "no such table: users" SQL error.
// That masks the error-based SQLi signal (the baseline already looks broken, so
// the scanner skips the endpoint). Seeding yields a clean 200 baseline, so an
// injected quote produces a detectable error-vs-baseline difference.
func seedVAmPIDatabase(t *testing.T, baseURL string) {
	t.Helper()
	// The container's readiness probe only checks that "/" responds; VAmPI's
	// /createdb (drop + recreate SQLite tables) can still transiently 500 for a
	// moment after that while the app finishes warming up. Retry until it seeds
	// rather than failing the whole scan on a startup-timing blip.
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	var lastStatus int
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/createdb")
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		status := resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if status == http.StatusOK {
			return
		}
		lastStatus, lastErr = status, nil
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("VAmPI /createdb never succeeded within 30s: last error: %v", lastErr)
	}
	t.Fatalf("VAmPI /createdb never returned 200 within 30s: last status HTTP %d", lastStatus)
}

// waitForEndpoint waits for an HTTP endpoint to become available
func waitForEndpoint(url string, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("endpoint %s not available after %v", url, timeout)
}
