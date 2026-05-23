package harness

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// ContainerConfig holds configuration for starting a vulnerable app container.
type ContainerConfig struct {
	Image         string
	ExposedPort   string
	WaitStrategy  wait.Strategy
	Env           map[string]string
	ReadyEndpoint string
}

// VulnerableApp represents a running vulnerable application container.
type VulnerableApp struct {
	Container  testcontainers.Container
	BaseURL    string
	ctx        context.Context
	composeApp *ComposeApp // non-nil for xbow apps managed via docker compose CLI
}

// StartContainer starts a Docker container with the given configuration.
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

	port := config.ExposedPort
	if len(port) > 4 && port[len(port)-4:] == "/tcp" {
		port = port[:len(port)-4]
	}

	mappedPort, err := container.MappedPort(ctx, port)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get mapped port: %w", err)
	}

	baseURL := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

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

// Stop terminates the container or compose stack.
func (app *VulnerableApp) Stop() error {
	if app.composeApp != nil {
		return app.composeApp.Stop()
	}
	if app.Container != nil {
		return app.Container.Terminate(app.ctx)
	}
	return nil
}

// ContainerConfigFromApp creates a ContainerConfig from an AppConfig definition.
func ContainerConfigFromApp(app AppConfig) ContainerConfig {
	exposedPort := app.ExposedPort
	if exposedPort == "" && app.Port > 0 {
		exposedPort = fmt.Sprintf("%d/tcp", app.Port)
	}

	startupTimeout := app.StartupTimeout
	if startupTimeout == 0 {
		startupTimeout = 120 * time.Second
	}

	portStr := exposedPort
	if len(portStr) > 4 && portStr[len(portStr)-4:] == "/tcp" {
		portStr = portStr[:len(portStr)-4]
	}

	waitEndpoint := app.WaitEndpoint
	if waitEndpoint == "" {
		waitEndpoint = "/"
	}

	return ContainerConfig{
		Image:       app.Image,
		ExposedPort: exposedPort,
		WaitStrategy: wait.ForHTTP(waitEndpoint).
			WithPort(portStr).
			WithStartupTimeout(startupTimeout),
		Env:           app.Env,
		ReadyEndpoint: waitEndpoint,
	}
}

// StartAppFromDefinition starts a Docker container based on an AppConfig.
func StartAppFromDefinition(ctx context.Context, app AppConfig) (*VulnerableApp, error) {
	switch app.Type {
	case "docker":
		config := ContainerConfigFromApp(app)
		return StartContainer(ctx, config)
	case "compose":
		return startComposeApp(ctx, app)
	case "xbow":
		composeApp, err := StartComposeApp(ctx, app)
		if err != nil {
			return nil, err
		}
		return &VulnerableApp{
			BaseURL:    composeApp.BaseURL,
			ctx:        ctx,
			composeApp: composeApp,
		}, nil
	case "external":
		return &VulnerableApp{
			BaseURL: app.BaseURL,
			ctx:     ctx,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported app type: %s", app.Type)
	}
}

// startComposeApp starts a Docker Compose application.
// For compose apps, we assume the services are managed externally (e.g., make crapi-up)
// and just verify the base URL is reachable.
func startComposeApp(ctx context.Context, app AppConfig) (*VulnerableApp, error) {
	baseURL := app.BaseURL
	if baseURL == "" {
		return nil, fmt.Errorf("compose app %s requires base_url", app.Name)
	}

	waitEndpoint := app.WaitEndpoint
	if waitEndpoint == "" {
		waitEndpoint = "/"
	}

	timeout := app.StartupTimeout
	if timeout == 0 {
		timeout = 120 * time.Second
	}

	if err := waitForEndpoint(baseURL+waitEndpoint, timeout); err != nil {
		return nil, fmt.Errorf("compose app %s not ready at %s: %w", app.Name, baseURL, err)
	}

	return &VulnerableApp{
		BaseURL: baseURL,
		ctx:     ctx,
	}, nil
}

// waitForEndpoint waits for an HTTP endpoint to become available.
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
