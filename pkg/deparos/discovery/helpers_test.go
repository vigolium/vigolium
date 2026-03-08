package discovery

import (
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/config"
)

// testServer creates a local HTTP server for testing.
// Returns 404 for any request to simulate a real web server.
// This allows fingerprint learning to complete quickly without network delays.
func testServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 for all requests
		// This is what fingerprint learning expects (learns 404 signatures)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
}

// testConfig creates a test configuration with the given server URL.
// Uses local test server instead of real domain to avoid network requests.
func testConfig(serverURL string) *config.Config {
	return &config.Config{
		Target: config.TargetConfig{
			StartURL: serverURL,
			Mode:     config.ModeFilesAndDirs,
			Recursion: config.RecursionConfig{
				Enabled:  true,
				MaxDepth: 16,
			},
		},
		Filenames: config.FilenameConfig{
			Wordlists: config.WordlistConfig{
				// Empty wordlist paths - tests that use this config
				// don't actually need wordlists
				ShortFilePath: "",
			},
		},
		Extensions: config.ExtensionConfig{
			TestCustom: true,
			// Use fewer extensions for faster tests
			CustomList: []string{"php"},
		},
		Engine: config.EngineConfig{
			CaseSensitivity:  config.CaseSensitive,
			DiscoveryThreads: 4,
			Timeout:          30 * time.Second,
		},
	}
}

// testEngine creates a test engine with fingerprint learner delay set to 0.
// This allows tests to complete quickly without waiting for request delays.
func testEngine(serverURL string) (*Engine, error) {
	cfg := testConfig(serverURL)
	return testEngineWithConfig(cfg)
}

// testEngineWithConfig creates a test engine from a given config.
// Sets fingerprint learner delay to 0 for fast tests.
func testEngineWithConfig(cfg *config.Config) (*Engine, error) {
	engine, err := NewEngine(cfg, nil)
	if err != nil {
		return nil, err
	}

	// Set learner delay to 0 for fast tests
	engine.fpLearner.SetDelay(0)

	return engine, nil
}
