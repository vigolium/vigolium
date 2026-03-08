//go:build e2e || canary

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
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

// Cleanup performs cleanup after tests
func (infra *TestInfra) Cleanup() {
	if infra.HostErrors != nil {
		infra.HostErrors.Close()
	}
	if infra.HostLimiter != nil {
		_ = infra.HostLimiter.Close()
	}
	network.Close()
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

// StartContainer starts a Docker container with the given configuration
func StartContainer(ctx context.Context, config ContainerConfig) (*VulnerableApp, error) {
	req := testcontainers.ContainerRequest{
		Image:        config.Image,
		ExposedPorts: []string{config.ExposedPort},
		WaitingFor:   config.WaitStrategy,
		Env:          config.Env,
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

	// Get the port from the config (strip /tcp suffix if present)
	port := config.ExposedPort
	if len(port) > 4 && port[len(port)-4:] == "/tcp" {
		port = port[:len(port)-4]
	}

	mappedPort, err := container.MappedPort(ctx, nat.Port(port))
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
