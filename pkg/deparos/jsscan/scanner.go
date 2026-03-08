package jsscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Scanner provides the jsscan analysis API.
// Thread-safe for concurrent use.
type Scanner struct {
	mu        sync.RWMutex
	extractor *Extractor
	config    *Config
	binary    *CachedBinary
}

// NewScanner creates a new Scanner with the given configuration.
// The jsscan binary is extracted lazily on first scan.
func NewScanner(config *Config) (*Scanner, error) {
	if config == nil {
		config = DefaultConfig()
	}

	extractor, err := NewExtractor(config)
	if err != nil {
		return nil, fmt.Errorf("create extractor: %w", err)
	}

	return &Scanner{
		extractor: extractor,
		config:    config,
	}, nil
}

// Scan analyzes the provided JavaScript content.
// This is the main API entry point for the jsscan package.
//
// The function:
// 1. Ensures the jsscan binary is available (extracts if needed)
// 2. Writes content to a temporary file
// 3. Executes jsscan binary with the temp file
// 4. Parses and returns the findings
//
// Thread-safe for concurrent calls.
func (s *Scanner) Scan(ctx context.Context, content []byte) (*ScanResult, error) {
	if len(content) == 0 {
		return &ScanResult{
			Requests:     []ExtractedRequest{},
			BytesScanned: 0,
		}, nil
	}

	startTime := time.Now()

	binary, err := s.getBinary()
	if err != nil {
		return nil, err
	}

	tmpFile, err := os.CreateTemp("", "jsscan-*.js")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("close temp file: %w", err)
	}

	requests, code, err := s.executeJsscan(ctx, binary.Path, tmpPath)
	if err != nil {
		return nil, err
	}

	return &ScanResult{
		Requests:     requests,
		Code:         code,
		ScanDuration: time.Since(startTime),
		BytesScanned: len(content),
	}, nil
}

// ScanFile scans a file directly without copying to temp file.
// Useful for scanning large files efficiently.
func (s *Scanner) ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	startTime := time.Now()

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	binary, err := s.getBinary()
	if err != nil {
		return nil, err
	}

	requests, code, err := s.executeJsscan(ctx, binary.Path, filePath)
	if err != nil {
		return nil, err
	}

	return &ScanResult{
		Requests:     requests,
		Code:         code,
		ScanDuration: time.Since(startTime),
		BytesScanned: int(info.Size()),
	}, nil
}

// ScanReader scans content from an io.Reader.
// Reads all content into memory before scanning.
func (s *Scanner) ScanReader(ctx context.Context, r io.Reader) (*ScanResult, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read content: %w", err)
	}
	return s.Scan(ctx, content)
}

// getBinary returns the cached binary or extracts it.
// Uses double-check locking pattern.
func (s *Scanner) getBinary() (*CachedBinary, error) {
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

	binary, err := s.extractor.GetBinary()
	if err != nil {
		return nil, err
	}

	s.binary = binary
	return binary, nil
}

// executeJsscan runs the jsscan binary and parses output.
func (s *Scanner) executeJsscan(ctx context.Context, binaryPath, inputPath string) ([]ExtractedRequest, *CodeRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, MaxScanTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, inputPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	if err != nil {
		if stdout.Len() == 0 {
			return nil, nil, fmt.Errorf("%w: %v, stderr: %s", ErrScanFailed, err, stderr.String())
		}
	}

	return parseJsscanOutput(stdout.Bytes())
}

// rawRecord is used to detect the type field before full parsing.
type rawRecord struct {
	Type string `json:"type"`
}

// parseJsscanOutput parses the JSONL output from jsscan.
// jsscan outputs one JSON object per line (JSONL format).
// Supports two record types: 'extractedRequest' and 'code'.
func parseJsscanOutput(output []byte) ([]ExtractedRequest, *CodeRecord, error) {
	if len(output) == 0 {
		return []ExtractedRequest{}, nil, nil
	}

	var requests []ExtractedRequest
	var code *CodeRecord

	lines := bytes.Split(output, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var raw rawRecord
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}

		switch raw.Type {
		case "extractedRequest":
			var req ExtractedRequest
			if err := json.Unmarshal(line, &req); err != nil {
				continue
			}
			requests = append(requests, req)
		case "code":
			var c CodeRecord
			if err := json.Unmarshal(line, &c); err != nil {
				continue
			}
			code = &c
		}
	}

	return requests, code, nil
}

// Checksum returns the checksum of the cached/extracted jsscan binary.
// Returns empty string if not yet extracted.
func (s *Scanner) Checksum() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.binary == nil {
		return ""
	}
	return s.binary.Checksum
}

// EnsureBinary pre-extracts the binary if not already cached.
// Useful for initialization to avoid delay on first scan.
func (s *Scanner) EnsureBinary() error {
	_, err := s.getBinary()
	return err
}

// Clear removes the cached binary and forces re-extraction on next scan.
func (s *Scanner) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.binary = nil
	return s.extractor.Clear()
}

// BinaryPath returns the path to the jsscan binary.
// Returns empty string if not yet extracted.
func (s *Scanner) BinaryPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.binary == nil {
		return ""
	}
	return s.binary.Path
}
