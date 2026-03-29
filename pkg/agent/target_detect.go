package agent

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

// DetectTargetFromSource attempts to infer the running URL of a web application
// from its source code directory. It checks (in priority order):
//  1. docker-compose.yml port mappings
//  2. .env / .env.example files for PORT variables
//  3. Common server entry files for listen() calls
//  4. Framework defaults as last resort
//
// Returns empty string if no target can be determined.
func DetectTargetFromSource(sourcePath string) string {
	if sourcePath == "" {
		return ""
	}

	// Resolve path
	sourcePath = expandHome(sourcePath)
	info, err := os.Stat(sourcePath)
	if err != nil || !info.IsDir() {
		return ""
	}

	// 1. Docker Compose port mappings
	if target := detectFromDockerCompose(sourcePath); target != "" {
		zap.L().Debug("target detected from docker-compose", zap.String("target", target))
		return target
	}

	// 2. Environment files
	if target := detectFromEnvFiles(sourcePath); target != "" {
		zap.L().Debug("target detected from env file", zap.String("target", target))
		return target
	}

	// 3. Server entry files (listen calls)
	if target := detectFromServerFiles(sourcePath); target != "" {
		zap.L().Debug("target detected from server entry file", zap.String("target", target))
		return target
	}

	// 4. Framework defaults
	if target := detectFromFramework(sourcePath); target != "" {
		zap.L().Debug("target detected from framework default", zap.String("target", target))
		return target
	}

	return ""
}

// dockerComposePortPattern matches port mappings like "8080:80", "3005:3000", "80:80".
var dockerComposePortPattern = regexp.MustCompile(`^\s*-?\s*"?(\d+):(\d+)"?\s*$`)

// detectFromDockerCompose parses docker-compose.yml for port mappings.
// Returns the first host port found as http://localhost:<port>.
func detectFromDockerCompose(dir string) string {
	composeFiles := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"compose.yml",
		"compose.yaml",
	}

	for _, name := range composeFiles {
		path := filepath.Join(dir, name)
		port := parseComposePort(path)
		if port != "" {
			return fmt.Sprintf("http://localhost:%s", port)
		}
	}
	return ""
}

// parseComposePort reads a docker-compose file and extracts the first host port mapping.
// Uses simple line-by-line parsing to avoid a YAML dependency.
func parseComposePort(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inPorts := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Detect "ports:" section
		if strings.HasPrefix(trimmed, "ports:") {
			inPorts = true
			continue
		}

		// If we're in a ports section, look for port mappings
		if inPorts {
			// End of ports section: non-indented, non-list line
			if trimmed != "" && !strings.HasPrefix(trimmed, "-") && !strings.HasPrefix(trimmed, "#") {
				inPorts = false
				continue
			}

			matches := dockerComposePortPattern.FindStringSubmatch(trimmed)
			if len(matches) == 3 {
				hostPort := matches[1]
				return hostPort
			}
		}
	}

	return ""
}

// envPortPattern matches PORT=, SERVER_PORT=, APP_PORT=, LISTEN_PORT= in .env files.
var envPortPattern = regexp.MustCompile(`^(?:PORT|SERVER_PORT|APP_PORT|LISTEN_PORT|HTTP_PORT)\s*=\s*(\d+)\s*$`)

// detectFromEnvFiles checks .env, .env.example, .env.defaults for PORT variables.
func detectFromEnvFiles(dir string) string {
	envFiles := []string{
		".env",
		".env.example",
		".env.defaults",
		".env.development",
		".env.local",
	}

	for _, name := range envFiles {
		path := filepath.Join(dir, name)
		port := parseEnvPort(path)
		if port != "" {
			return fmt.Sprintf("http://localhost:%s", port)
		}
	}
	return ""
}

// parseEnvPort reads an env file and returns the first PORT value found.
func parseEnvPort(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		matches := envPortPattern.FindStringSubmatch(line)
		if len(matches) == 2 {
			return matches[1]
		}
	}
	return ""
}

// listenPortPatterns match common server listen patterns across languages.
var listenPortPatterns = []*regexp.Regexp{
	// Node.js/Express: app.listen(3000, ...) or server.listen(3000)
	regexp.MustCompile(`\.listen\(\s*(\d{2,5})\b`),
	// Go: http.ListenAndServe(":8080", ...) or ListenAndServe(":8080"
	regexp.MustCompile(`ListenAndServe\(\s*"?:(\d{2,5})"?`),
	// Python/Flask/FastAPI: app.run(port=8000) or uvicorn.run(..., port=8000)
	regexp.MustCompile(`port\s*=\s*(\d{2,5})`),
	// Ruby/Rails: Puma.bind "tcp://0.0.0.0:3000"
	regexp.MustCompile(`tcp://[^:]+:(\d{2,5})`),
	// PHP: $server->listen("0.0.0.0:8000")
	regexp.MustCompile(`listen\(\s*"[^:]*:(\d{2,5})"`),
}

// serverEntryFiles are common filenames for server entry points.
var serverEntryFiles = []string{
	"app.js", "server.js", "index.js", "main.js",
	"app.ts", "server.ts", "index.ts", "main.ts",
	"app.py", "main.py", "server.py", "manage.py", "wsgi.py", "asgi.py",
	"main.go", "server.go", "cmd/main.go", "cmd/server.go",
	"config.ru", "Procfile",
}

// detectFromServerFiles checks common server entry files for listen port patterns.
func detectFromServerFiles(dir string) string {
	for _, name := range serverEntryFiles {
		path := filepath.Join(dir, name)
		port := parseServerFilePort(path)
		if port != "" {
			return fmt.Sprintf("http://localhost:%s", port)
		}
	}

	// Also check src/ subdirectory
	srcDir := filepath.Join(dir, "src")
	if info, err := os.Stat(srcDir); err == nil && info.IsDir() {
		for _, name := range serverEntryFiles {
			path := filepath.Join(srcDir, name)
			port := parseServerFilePort(path)
			if port != "" {
				return fmt.Sprintf("http://localhost:%s", port)
			}
		}
	}

	return ""
}

// maxServerFileReadBytes limits how much of a server entry file we read.
// Listen port declarations are near the top; no need to read large bundled files.
const maxServerFileReadBytes = 64 * 1024

// parseServerFilePort reads the beginning of a source file and returns the first listen port found.
func parseServerFilePort(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	buf := make([]byte, maxServerFileReadBytes)
	n, _ := f.Read(buf)
	if n == 0 {
		return ""
	}

	content := string(buf[:n])
	for _, pattern := range listenPortPatterns {
		matches := pattern.FindStringSubmatch(content)
		if len(matches) == 2 {
			return matches[1]
		}
	}
	return ""
}

// frameworkDefaults maps framework indicators to default ports.
// Only included for frameworks with strong default port conventions.
// Generic indicators like go.mod are excluded since they don't imply a web server.
var frameworkDefaults = []struct {
	indicator string // file to check for
	port      string
}{
	{"package.json", "3000"}, // Node.js/Express default
	{"Gemfile", "3000"},      // Rails default
}

// detectFromFramework checks for framework indicator files and returns the default port.
func detectFromFramework(dir string) string {
	for _, fw := range frameworkDefaults {
		path := filepath.Join(dir, fw.indicator)
		if _, err := os.Stat(path); err == nil {
			return fmt.Sprintf("http://localhost:%s", fw.port)
		}
	}
	return ""
}
