package source

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectTargetFromSource_DockerCompose(t *testing.T) {
	dir := t.TempDir()

	// Create docker-compose.yml with port mapping
	compose := `version: '3'
services:
  web:
    build: .
    ports:
      - "8025:8080"
    environment:
      - DB_HOST=db
  db:
    image: postgres
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	target := DetectTargetFromSource(dir)
	if target != "http://localhost:8025" {
		t.Errorf("expected http://localhost:8025, got %q", target)
	}
}

func TestDetectTargetFromSource_ComposeYaml(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  app:
    ports:
      - "3005:3000"
`
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	target := DetectTargetFromSource(dir)
	if target != "http://localhost:3005" {
		t.Errorf("expected http://localhost:3005, got %q", target)
	}
}

func TestDetectTargetFromSource_EnvFile(t *testing.T) {
	dir := t.TempDir()

	envContent := `# Application config
DATABASE_URL=postgres://localhost/db
PORT=5000
SECRET_KEY=abc123
`
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	target := DetectTargetFromSource(dir)
	if target != "http://localhost:5000" {
		t.Errorf("expected http://localhost:5000, got %q", target)
	}
}

func TestDetectTargetFromSource_EnvExample(t *testing.T) {
	dir := t.TempDir()

	envContent := `SERVER_PORT=8080
`
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	target := DetectTargetFromSource(dir)
	if target != "http://localhost:8080" {
		t.Errorf("expected http://localhost:8080, got %q", target)
	}
}

func TestDetectTargetFromSource_ServerFile(t *testing.T) {
	dir := t.TempDir()

	serverJS := `const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
  res.json([]);
});

app.listen(4000, () => {
  console.log('Server running on port 4000');
});
`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(serverJS), 0644); err != nil {
		t.Fatal(err)
	}

	target := DetectTargetFromSource(dir)
	if target != "http://localhost:4000" {
		t.Errorf("expected http://localhost:4000, got %q", target)
	}
}

func TestDetectTargetFromSource_GoServer(t *testing.T) {
	dir := t.TempDir()

	mainGo := `package main

import (
	"net/http"
)

func main() {
	http.ListenAndServe(":9090", nil)
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatal(err)
	}

	target := DetectTargetFromSource(dir)
	if target != "http://localhost:9090" {
		t.Errorf("expected http://localhost:9090, got %q", target)
	}
}

func TestDetectTargetFromSource_PythonFlask(t *testing.T) {
	dir := t.TempDir()

	appPy := `from flask import Flask

app = Flask(__name__)

@app.route('/api/data')
def get_data():
    return {'data': []}

if __name__ == '__main__':
    app.run(port=8888, debug=True)
`
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(appPy), 0644); err != nil {
		t.Fatal(err)
	}

	target := DetectTargetFromSource(dir)
	if target != "http://localhost:8888" {
		t.Errorf("expected http://localhost:8888, got %q", target)
	}
}

func TestDetectTargetFromSource_FrameworkDefault(t *testing.T) {
	dir := t.TempDir()

	// Create package.json (Node.js indicator) with no port info
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"app"}`), 0644); err != nil {
		t.Fatal(err)
	}

	target := DetectTargetFromSource(dir)
	if target != "http://localhost:3000" {
		t.Errorf("expected http://localhost:3000 (Node.js default), got %q", target)
	}
}

func TestDetectTargetFromSource_Empty(t *testing.T) {
	dir := t.TempDir()

	// Empty directory — no indicators
	target := DetectTargetFromSource(dir)
	if target != "" {
		t.Errorf("expected empty string for empty dir, got %q", target)
	}
}

func TestDetectTargetFromSource_Priority(t *testing.T) {
	dir := t.TempDir()

	// docker-compose should win over .env
	compose := `services:
  app:
    ports:
      - "9999:3000"
`
	envContent := `PORT=5555
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0644); err != nil {
		t.Fatal(err)
	}

	target := DetectTargetFromSource(dir)
	if target != "http://localhost:9999" {
		t.Errorf("expected docker-compose port (9999) to win, got %q", target)
	}
}

func TestDetectTargetFromSource_InvalidPath(t *testing.T) {
	target := DetectTargetFromSource("/nonexistent/path/12345")
	if target != "" {
		t.Errorf("expected empty for nonexistent path, got %q", target)
	}
}

func TestDetectTargetFromSource_EmptyString(t *testing.T) {
	target := DetectTargetFromSource("")
	if target != "" {
		t.Errorf("expected empty for empty input, got %q", target)
	}
}

func TestParseComposePort_QuotedPorts(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  web:
    ports:
      - "80:80"
`
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	port := parseComposePort(path)
	if port != "80" {
		t.Errorf("expected 80, got %q", port)
	}
}
