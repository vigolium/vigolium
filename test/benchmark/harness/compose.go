package harness

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ComposeApp represents a running Docker Compose application managed via the CLI.
type ComposeApp struct {
	ProjectName string
	ProjectDir  string
	BaseURL     string
}

// StartComposeApp builds and starts a Docker Compose project, discovers the mapped port,
// and waits for the application to become ready.
func StartComposeApp(ctx context.Context, app AppConfig) (*ComposeApp, error) {
	projectDir := os.ExpandEnv(app.BuildContext)
	if projectDir == "" {
		return nil, fmt.Errorf("xbow app %s: build_context is empty (XBOW_SOURCE_DIR may not be set)", app.Name)
	}

	composeFile := projectDir + "/docker-compose.yml"
	if _, err := os.Stat(composeFile); err != nil {
		return nil, fmt.Errorf("xbow app %s: docker-compose.yml not found at %s: %w", app.Name, composeFile, err)
	}

	projectName := "xbow-" + app.Name

	// Build the images
	buildArgs := []string{
		"compose", "-f", composeFile, "-p", projectName,
		"build", "--build-arg", "FLAG=test",
	}
	if err := runDockerCompose(ctx, buildArgs, projectDir); err != nil {
		return nil, fmt.Errorf("xbow app %s: build failed: %w", app.Name, err)
	}

	// Start the stack
	upArgs := []string{
		"compose", "-f", composeFile, "-p", projectName,
		"up", "-d", "--wait",
	}
	if err := runDockerCompose(ctx, upArgs, projectDir); err != nil {
		// Clean up on failure
		_ = stopComposeProject(composeFile, projectName)
		return nil, fmt.Errorf("xbow app %s: up failed: %w", app.Name, err)
	}

	// Discover the mapped port
	serviceName := app.ServiceName
	if serviceName == "" {
		serviceName = "app"
	}
	internalPort := app.InternalPort
	if internalPort == 0 {
		internalPort = 80
	}

	hostPort, err := getComposeMappedPort(ctx, composeFile, projectName, serviceName, internalPort)
	if err != nil {
		_ = stopComposeProject(composeFile, projectName)
		return nil, fmt.Errorf("xbow app %s: port discovery failed: %w", app.Name, err)
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%s", hostPort)

	// Wait for the endpoint to become available
	waitEndpoint := app.WaitEndpoint
	if waitEndpoint == "" {
		waitEndpoint = "/"
	}
	timeout := app.StartupTimeout
	if timeout == 0 {
		timeout = 180 * time.Second
	}

	if err := waitForEndpoint(baseURL+waitEndpoint, timeout); err != nil {
		_ = stopComposeProject(composeFile, projectName)
		return nil, fmt.Errorf("xbow app %s: not ready at %s: %w", app.Name, baseURL+waitEndpoint, err)
	}

	return &ComposeApp{
		ProjectName: projectName,
		ProjectDir:  projectDir,
		BaseURL:     baseURL,
	}, nil
}

// Stop tears down the Docker Compose project, removing volumes and orphan containers.
func (c *ComposeApp) Stop() error {
	composeFile := c.ProjectDir + "/docker-compose.yml"
	return stopComposeProject(composeFile, c.ProjectName)
}

// stopComposeProject runs docker compose down for a project.
func stopComposeProject(composeFile, projectName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	args := []string{
		"compose", "-f", composeFile, "-p", projectName,
		"down", "-v", "--remove-orphans",
	}
	return runDockerCompose(ctx, args, "")
}

// getComposeMappedPort discovers the host-side mapped port for a service's internal port.
func getComposeMappedPort(ctx context.Context, composeFile, projectName, serviceName string, internalPort int) (string, error) {
	args := []string{
		"compose", "-f", composeFile, "-p", projectName,
		"port", serviceName, fmt.Sprintf("%d", internalPort),
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker compose port failed: %w (stderr: %s)", err, stderr.String())
	}

	// Output is like "0.0.0.0:32769" or "127.0.0.1:32769"
	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return "", fmt.Errorf("no port mapping found for %s:%d", serviceName, internalPort)
	}

	parts := strings.SplitN(output, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected port output format: %q", output)
	}

	return parts[1], nil
}

// runDockerCompose executes a docker compose command and returns any error.
func runDockerCompose(ctx context.Context, args []string, dir string) error {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stderr = &stderr
	cmd.Stdout = os.Stdout // Stream build/startup output for visibility

	if dir != "" {
		cmd.Dir = dir
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w (stderr: %s)", err, stderr.String())
	}
	return nil
}
