package jstangle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Scanner manages the embedded jstangle binary and its capability handshake.
// Analysis runs through the Service worker pool (length-prefixed protocol);
// Scanner itself only owns binary extraction and the negotiated capability
// record that the pool relies on.
// Thread-safe for concurrent use.
type Scanner struct {
	mu           sync.RWMutex
	extractor    *Extractor
	config       *Config
	binary       *CachedBinary
	capabilities *Capabilities
}

// NewScanner creates a new Scanner with the given configuration.
// The jstangle binary is extracted lazily on first use.
func NewScanner(config *Config) (*Scanner, error) {
	if config == nil {
		config = DefaultConfig()
	}

	extractor, err := NewExtractor(config)
	if err != nil {
		return nil, fmt.Errorf("create extractor: %w", err)
	}

	s := &Scanner{
		extractor: extractor,
		config:    config,
	}
	cleanupStaleTempFiles()

	return s, nil
}

var staleCleanupOnce sync.Once

func cleanupStaleTempFiles() {
	staleCleanupOnce.Do(func() {
		entries, err := os.ReadDir(os.TempDir())
		if err != nil {
			return
		}
		cutoff := time.Now().Add(-24 * time.Hour)
		for _, entry := range entries {
			name := entry.Name()
			isJobDir := entry.IsDir() && strings.HasPrefix(name, "jstangle-job-")
			isTempFile := !entry.IsDir() && strings.HasPrefix(name, "jstangle-")
			if !isJobDir && !isTempFile {
				continue
			}
			info, statErr := entry.Info()
			if statErr == nil && info.ModTime().Before(cutoff) {
				_ = os.RemoveAll(filepath.Join(os.TempDir(), name))
			}
		}
	})
}

func normalizeScanOptions(opts ScanOptions) ScanOptions {
	if opts.Profile == "" {
		opts.Profile = ProfileLegacy
	}
	if opts.MaxInputBytes <= 0 {
		opts.MaxInputBytes = DefaultMaxInputBytes
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if opts.MaxArtifactBytes <= 0 {
		opts.MaxArtifactBytes = DefaultMaxArtifactBytes
	}
	if opts.MaxRequests <= 0 {
		opts.MaxRequests = 1000
	}
	if opts.MaxASTNodes <= 0 {
		opts.MaxASTNodes = DefaultMaxASTNodes
	}
	if opts.Deadline <= 0 {
		opts.Deadline = 60 * time.Second
	}
	return opts
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

	caps, err := queryCapabilities(binary.Path)
	if err != nil {
		return nil, err
	}
	if caps.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("%w: helper=%d client=%d", ErrIncompatibleProtocol, caps.ProtocolVersion, ProtocolVersion)
	}

	s.binary = binary
	s.capabilities = caps
	return binary, nil
}

func queryCapabilities(binaryPath string) (*Capabilities, error) {
	// First launch of a freshly extracted standalone Bun executable can include
	// platform signature/quarantine checks. Keep this bounded, but do not treat a
	// normal cold start as a protocol failure.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, "--capabilities")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: query capabilities: %w", ErrIncompatibleProtocol, err)
	}
	if len(output) > 1024*1024 {
		return nil, fmt.Errorf("%w: capability output too large", ErrIncompatibleProtocol)
	}
	var caps Capabilities
	if err := json.Unmarshal(bytes.TrimSpace(output), &caps); err != nil {
		return nil, fmt.Errorf("%w: decode capabilities: %w", ErrIncompatibleProtocol, err)
	}
	if caps.Type != "capabilities" || caps.SourceHash == "" {
		return nil, fmt.Errorf("%w: invalid capability record", ErrIncompatibleProtocol)
	}
	return &caps, nil
}

func loadArtifacts(result *ScanResult, jobDir string, maxArtifactBytes int64) error {
	root, err := filepath.Abs(jobDir)
	if err != nil {
		return fmt.Errorf("resolve artifact directory: %w", err)
	}
	if evaluated, evalErr := filepath.EvalSymlinks(root); evalErr == nil {
		root = evaluated
	}
	for i := range result.Artifacts {
		artifact := &result.Artifacts[i]
		path, err := filepath.Abs(artifact.Path)
		if err != nil {
			return fmt.Errorf("resolve artifact path: %w", err)
		}
		if evaluated, evalErr := filepath.EvalSymlinks(path); evalErr == nil {
			path = evaluated
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return fmt.Errorf("%w: artifact path escapes job directory", ErrScanFailed)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("read artifact metadata: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: artifact is not a regular file", ErrScanFailed)
		}
		if info.Size() != artifact.ByteLength || info.Size() < 0 || info.Size() > maxArtifactBytes {
			return fmt.Errorf("%w: invalid artifact size %d", ErrOutputTooLarge, info.Size())
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read artifact: %w", err)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(content))
		if !strings.EqualFold(digest, artifact.SHA256) {
			return fmt.Errorf("%w: artifact checksum mismatch", ErrScanFailed)
		}
		artifact.Content = content
		artifact.Path = ""
		switch artifact.ArtifactType {
		case "transformedSource":
			result.Code = &CodeRecord{Filename: artifact.Filename, Content: string(content)}
		case "beautifiedSource":
			result.Beautified = &BeautifiedCode{
				Filename: artifact.Filename, Format: artifact.Format,
				ModuleCount: artifact.ModuleCount, ModulePaths: artifact.ModulePaths,
				Changed: true, Content: string(content),
			}
		}
	}
	if result.Analysis != nil {
		for i := range result.Analysis.Artifacts {
			result.Analysis.Artifacts[i].Path = ""
		}
	}
	return nil
}

// appendAnalysisRecord decodes each protocol-v2 record family delivered in the
// framed worker's analysisResult envelope into the compact Go ScanResult.
func appendAnalysisRecord(result *ScanResult, record json.RawMessage) {
	var kind struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(record, &kind); err != nil {
		result.MalformedRecords++
		return
	}
	decode := func(target any) bool {
		if err := json.Unmarshal(record, target); err != nil {
			result.MalformedRecords++
			return false
		}
		return true
	}
	switch kind.Kind {
	case "httpRequest":
		var fact HTTPRequestFact
		if decode(&fact) {
			result.RequestFacts = append(result.RequestFacts, fact)
			result.Requests = append(result.Requests, legacyRequestFromFact(fact))
		}
	case "domFlow":
		var fact DomFlowFact
		if decode(&fact) {
			result.DomFlowFacts = append(result.DomFlowFacts, fact)
			result.DomFlows = append(result.DomFlows, DomFlow{
				FlowType: fact.FlowType, Source: fact.Source, Sink: fact.Sink,
				Snippet: fact.Snippet, Line: fact.Line,
			})
		}
	case "assetReference":
		var fact AssetReferenceFact
		if decode(&fact) {
			result.AssetFacts = append(result.AssetFacts, fact)
		}
	case "graphqlOperation":
		var fact GraphQLOperationFact
		if decode(&fact) {
			result.GraphQLOperations = append(result.GraphQLOperations, fact)
		}
	case "websocket":
		var fact WebSocketFact
		if decode(&fact) {
			result.WebSockets = append(result.WebSockets, fact)
		}
	case "eventSource":
		var fact EventSourceFact
		if decode(&fact) {
			result.EventSources = append(result.EventSources, fact)
		}
	case "clientRoute":
		var fact ClientRouteFact
		if decode(&fact) {
			result.ClientRoutes = append(result.ClientRoutes, fact)
		}
	case "browserSecurityFlow":
		var fact BrowserSecurityFlowFact
		if decode(&fact) {
			result.BrowserFlows = append(result.BrowserFlows, fact)
		}
	default:
		result.UnknownRecords++
		result.appendUnknownRecord(record)
	}
}

func (r *ScanResult) appendUnknownRecord(record []byte) {
	r.UnknownRecordData = append(r.UnknownRecordData, json.RawMessage(append([]byte(nil), record...)))
}

func renderFieldTemplates(fields []FieldTemplate) string {
	var b strings.Builder
	for i, field := range fields {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(field.Name.Rendered)
		b.WriteByte('=')
		b.WriteString(field.Value.Rendered)
	}
	return b.String()
}

func legacyRequestFromFact(fact HTTPRequestFact) ExtractedRequest {
	headers := make([]string, 0, len(fact.Headers))
	for _, header := range fact.Headers {
		headers = append(headers, header.Name.Rendered+": "+header.Value.Rendered)
	}
	cookies := make([]string, 0, len(fact.Cookies))
	for _, cookie := range fact.Cookies {
		cookies = append(cookies, cookie.Name.Rendered+"="+cookie.Value.Rendered)
	}
	body := ""
	if fact.Body != nil {
		body = fact.Body.Value.Rendered
	}
	return ExtractedRequest{
		URL: fact.URL.Rendered, Method: fact.Method.Rendered,
		Params: renderFieldTemplates(fact.Query), Body: body,
		Headers: headers, Cookies: cookies,
	}
}

// LegacyRequestFromFact projects a typed v2 fact into the v1 compatibility
// shape. New replay code should retain the original fact alongside this view.
func LegacyRequestFromFact(fact HTTPRequestFact) ExtractedRequest {
	return legacyRequestFromFact(fact)
}

// Checksum returns the checksum of the cached/extracted jstangle binary.
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

// Capabilities validates the helper and returns a defensive copy of its
// negotiated protocol metadata.
func (s *Scanner) Capabilities() (*Capabilities, error) {
	if _, err := s.getBinary(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.capabilities == nil {
		return nil, ErrIncompatibleProtocol
	}
	copy := *s.capabilities
	copy.Capabilities = append([]string(nil), s.capabilities.Capabilities...)
	copy.Profiles = append([]string(nil), s.capabilities.Profiles...)
	copy.Framing = append([]string(nil), s.capabilities.Framing...)
	return &copy, nil
}

// Clear removes the cached binary and forces re-extraction on next scan.
func (s *Scanner) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.binary = nil
	s.capabilities = nil
	return s.extractor.Clear()
}

// Close satisfies lifecycle-oriented callers. Scanner owns no long-lived
// subprocess or input path; each invocation removes its files synchronously.
// Persistent workers are owned and closed by Service.
func (s *Scanner) Close() error { return nil }

// BinaryPath returns the path to the jstangle binary.
// Returns empty string if not yet extracted.
func (s *Scanner) BinaryPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.binary == nil {
		return ""
	}
	return s.binary.Path
}
