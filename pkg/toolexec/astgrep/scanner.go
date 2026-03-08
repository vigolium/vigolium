package astgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/toolexec"
	"go.uber.org/zap"
)

// Scanner provides the ast-grep scanning API.
// Thread-safe for concurrent use.
type Scanner struct {
	mu         sync.RWMutex
	downloader *Downloader
	config     *Config
	binary     *toolexec.CachedBinary
}

// NewScanner creates a new Scanner with the given configuration.
// The ast-grep binary is resolved lazily on first scan.
func NewScanner(config *Config) (*Scanner, error) {
	if config == nil {
		config = DefaultConfig()
	}

	downloader, err := NewDownloader(config)
	if err != nil {
		return nil, fmt.Errorf("create downloader: %w", err)
	}

	return &Scanner{
		downloader: downloader,
		config:     config,
	}, nil
}

// ScanDir runs ast-grep scan on the given directory with rules from rulesDir.
// Returns parsed matches from the JSON output.
func (s *Scanner) ScanDir(ctx context.Context, targetDir, rulesDir string) (*ScanResult, error) {
	startTime := time.Now()

	binary, err := s.getBinary(ctx)
	if err != nil {
		return nil, err
	}

	matches, err := s.executeScan(ctx, binary.Path, targetDir, rulesDir)
	if err != nil {
		return nil, err
	}

	return &ScanResult{
		Matches:      matches,
		ScanDuration: time.Since(startTime),
		RuleSet:      rulesDir,
	}, nil
}

// ScanDirWithFramework extracts embedded rules for the given framework,
// then runs ScanDir with those rules.
func (s *Scanner) ScanDirWithFramework(ctx context.Context, targetDir, framework string) (*ScanResult, error) {
	rulesDir, err := ExtractRules(framework, "")
	if err != nil {
		return nil, fmt.Errorf("extract rules for %s: %w", framework, err)
	}

	result, err := s.ScanDir(ctx, targetDir, rulesDir)
	if err != nil {
		return nil, err
	}
	result.RuleSet = framework
	return result, nil
}

// ScanDirWithRules scans targetDir using all embedded rules, optionally filtered by ruleFilter.
// If ruleFilter is empty, all rules from all frameworks are used.
// When s.config.RulesDir is set and no filter is active, it is used directly
// instead of extracting embedded rules to a temp directory.
func (s *Scanner) ScanDirWithRules(ctx context.Context, targetDir, ruleFilter string) (*ScanResult, error) {
	var rulesDir string
	var err error

	if ruleFilter == "" && s.config.RulesDir != "" {
		// Use pre-extracted rules directory from config (e.g. ~/.vigolium/sast-rules/astgrep/)
		rulesDir = s.config.RulesDir
	} else if ruleFilter == "" {
		rulesDir, err = ExtractAllRules("")
	} else {
		rulesDir, err = ExtractMatchingRules(ruleFilter, "")
	}
	if err != nil {
		return nil, fmt.Errorf("extract rules: %w", err)
	}

	result, scanErr := s.ScanDir(ctx, targetDir, rulesDir)
	if scanErr != nil {
		return nil, scanErr
	}
	if ruleFilter != "" {
		result.RuleSet = "filter:" + ruleFilter
	} else {
		result.RuleSet = "all"
	}
	return result, nil
}

// getBinary returns the cached binary or fetches it.
func (s *Scanner) getBinary(ctx context.Context) (*toolexec.CachedBinary, error) {
	s.mu.RLock()
	if s.binary != nil {
		binary := s.binary
		s.mu.RUnlock()
		return binary, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.binary != nil {
		return s.binary, nil
	}

	binary, err := s.downloader.GetBinary(ctx)
	if err != nil {
		return nil, err
	}

	s.binary = binary
	return binary, nil
}

// executeScan runs the ast-grep binary and parses JSON output.
func (s *Scanner) executeScan(ctx context.Context, binaryPath, targetDir, rulesDir string) ([]Match, error) {
	// Remove any stale ast-grep-config.yaml inside the rules directory.
	// ast-grep treats all .yaml files in ruleDirs as rules; the config file
	// is not a valid rule and causes parse errors.
	os.Remove(filepath.Join(rulesDir, "ast-grep-config.yaml"))

	// Generate a temp config file outside the rules directory so that ast-grep
	// does not try to parse it as a rule (all .yaml files in ruleDirs are scanned).
	absRulesDir, err := filepath.Abs(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("resolve rules dir: %w", err)
	}
	tmpConfig, err := os.CreateTemp("", "sg-config-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("create temp config: %w", err)
	}
	configPath := tmpConfig.Name()
	defer os.Remove(configPath)

	configContent := fmt.Sprintf("ruleDirs:\n  - %s\n", absRulesDir)
	if _, err := tmpConfig.WriteString(configContent); err != nil {
		tmpConfig.Close()
		return nil, fmt.Errorf("write temp config: %w", err)
	}
	tmpConfig.Close()

	result, err := toolexec.Run(ctx, binaryPath, "scan", "--config", configPath, "--json", targetDir)
	if err != nil {
		var stderr string
		if result != nil {
			stderr = string(result.Stderr)
		}
		return nil, fmt.Errorf("%w: %v, stderr: %s", ErrScanFailed, err, stderr)
	}

	// Write output to a temp file for later review and parse from it.
	if len(result.Stdout) > 0 {
		if f, tmpErr := os.CreateTemp("", "sast-astgrep-*.json"); tmpErr == nil {
			f.Write(result.Stdout)
			f.Close()
			zap.L().Debug("ast-grep output file",
				zap.String("output_file", f.Name()),
				zap.Int("bytes", len(result.Stdout)))
		}
	}

	return parseAstGrepOutput(result.Stdout)
}

// parseAstGrepOutput parses the JSON output from ast-grep.
func parseAstGrepOutput(output []byte) ([]Match, error) {
	if len(output) == 0 {
		return []Match{}, nil
	}

	var matches []Match
	if err := json.Unmarshal(output, &matches); err != nil {
		return nil, fmt.Errorf("parse ast-grep output: %w", err)
	}

	return matches, nil
}

// Version returns the version of the cached/downloaded ast-grep binary.
func (s *Scanner) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.binary == nil {
		return ""
	}
	return s.binary.Version
}

// EnsureBinary pre-downloads the binary if not already cached.
func (s *Scanner) EnsureBinary(ctx context.Context) error {
	_, err := s.getBinary(ctx)
	return err
}

// Clear removes the cached binary and forces re-download on next scan.
func (s *Scanner) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.binary = nil
	return s.downloader.Clear()
}

// BinaryPath returns the path to the ast-grep binary.
func (s *Scanner) BinaryPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.binary == nil {
		return ""
	}
	return s.binary.Path
}
