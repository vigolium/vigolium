package kingfisher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/toolexec"
)

// Scanner provides the kingfisher scanning API.
// Thread-safe for concurrent use.
type Scanner struct {
	mu         sync.RWMutex
	downloader *Downloader
	config     *Config
	binary     *toolexec.CachedBinary
}

// NewScanner creates a new Scanner with the given configuration.
// The kingfisher binary is downloaded lazily on first scan.
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

// Scan analyzes the provided body bytes for credentials and security issues.
func (s *Scanner) Scan(ctx context.Context, body []byte) (*ScanResult, error) {
	if len(body) == 0 {
		return &ScanResult{
			Findings:     []Finding{},
			BytesScanned: 0,
		}, nil
	}

	startTime := time.Now()

	binary, err := s.getBinary(ctx)
	if err != nil {
		return nil, err
	}

	tmpFile, err := os.CreateTemp("", "kingfisher-scan-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(body); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("close temp file: %w", err)
	}

	findings, err := s.executeKingfisher(ctx, binary.Path, tmpPath)
	if err != nil {
		return nil, err
	}

	return &ScanResult{
		Findings:     findings,
		ScanDuration: time.Since(startTime),
		BytesScanned: len(body),
	}, nil
}

// ScanDir scans all files in a directory for secrets in a single invocation.
// Findings include the Path field set to the file path within the directory,
// allowing callers to map findings back to individual files.
func (s *Scanner) ScanDir(ctx context.Context, dirPath string) (*ScanResult, error) {
	startTime := time.Now()

	info, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("stat dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", dirPath)
	}

	binary, err := s.getBinary(ctx)
	if err != nil {
		return nil, err
	}

	findings, err := s.executeKingfisher(ctx, binary.Path, dirPath)
	if err != nil {
		return nil, err
	}

	return &ScanResult{
		Findings:     findings,
		ScanDuration: time.Since(startTime),
	}, nil
}

// ScanFile scans a file directly without copying to temp file.
func (s *Scanner) ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	startTime := time.Now()

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	binary, err := s.getBinary(ctx)
	if err != nil {
		return nil, err
	}

	findings, err := s.executeKingfisher(ctx, binary.Path, filePath)
	if err != nil {
		return nil, err
	}

	return &ScanResult{
		Findings:     findings,
		ScanDuration: time.Since(startTime),
		BytesScanned: int(info.Size()),
	}, nil
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

// executeKingfisher runs the kingfisher binary and parses output.
// NOTE: Previously used context.Background() — now correctly propagates ctx.
func (s *Scanner) executeKingfisher(ctx context.Context, binaryPath, inputPath string) ([]Finding, error) {
	result, err := toolexec.Run(ctx, binaryPath, "scan", "-f", "jsonl", "-n", "--no-update-check", "-q", inputPath)
	if err != nil {
		var stderr string
		if result != nil {
			stderr = string(result.Stderr)
		}
		return nil, fmt.Errorf("%w: %w, stderr: %s", ErrScanFailed, err, stderr)
	}

	return parseKingfisherOutput(result.Stdout)
}

// parseKingfisherOutput parses the JSON output from kingfisher.
// Kingfisher outputs one JSON object per line (JSONL format).
func parseKingfisherOutput(output []byte) ([]Finding, error) {
	if len(output) == 0 {
		return []Finding{}, nil
	}

	var findings []Finding

	// Try parsing as JSON array first
	if err := json.Unmarshal(output, &findings); err == nil {
		return findings, nil
	}

	// Try parsing as JSONL (one JSON object per line)
	lines := bytes.Split(output, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var finding Finding
		if err := json.Unmarshal(line, &finding); err != nil {
			continue // Skip invalid lines
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// Version returns the version of the cached/downloaded kingfisher binary.
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

// BinaryPath returns the path to the kingfisher binary.
func (s *Scanner) BinaryPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.binary == nil {
		return ""
	}
	return s.binary.Path
}
