package discovery

import (
	"context"
	"net/url"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/jsscan"
	"github.com/vigolium/vigolium/pkg/deparos/reqcache"
	"github.com/vigolium/vigolium/pkg/deparos/scope"
	"github.com/vigolium/vigolium/pkg/deparos/waf"
)

// Task provides configuration and payloads for content discovery.
// Tasks are immutable configuration objects - execution is handled by PayloadCoordinator.
// N workers consume payloads from task.PayloadProvider() concurrently.
type Task interface {
	// Hash returns a FNV-1a 64-bit hash for task deduplication.
	Hash() uint64

	// Priority returns the task's priority (0-14, lower = higher priority).
	Priority() uint8

	// Description returns a human-readable task description.
	Description() string

	// FoundByName returns a short identifier for this task type.
	// Used for result attribution (e.g., "spider-file", "short-dir", "numeric").
	FoundByName() string

	// PayloadProvider returns the provider for payload iteration.
	// Thread-safe - multiple workers can call Next() concurrently.
	PayloadProvider() payload.Provider

	// FullURL returns the full URL for this task (scheme://host + path).
	FullURL() []byte

	// Extension returns the extension to test per payload.
	// Empty string means no extension (test payload alone).
	Extension() string

	// Depth returns the discovery depth for recursive task generation.
	Depth() uint16

	// IsFromSpider returns true if task originated from spider link extraction.
	// Spider tasks bypass module filtering (only dedupe applies).
	IsFromSpider() bool

	// Expand iterates over all URLs this task generates and invokes callback for each.
	// Each task type implements its own URL building logic.
	// Returns error if expansion fails (e.g., context cancelled).
	Expand(ctx context.Context, callback func(url string, depth uint16)) error
}

// Callbacks holds discovery event handlers.
// Invoked by workers when resources are discovered.
// All callbacks must be thread-safe.
type Callbacks struct {
	// OnResult is called for every HTTP response.
	OnResult func(result *Result)

	// OnDirectoryDiscovered is called when a directory is found.
	OnDirectoryDiscovered func(url string, depth uint16) error

	// OnFileDiscovered is called when a file is found.
	OnFileDiscovered func(url string, depth uint16) error

	// AddObservedName adds a name to observed collection (from JS path extraction).
	AddObservedName func(name string)

	// AddObservedPath adds a path to observed collection (from JS path extraction).
	AddObservedPath func(path string)

	// HTTPClient is the client used for HTTP requests.
	HTTPClient http.HTTPClient

	// Analyzer is used for response analysis.
	Analyzer *http.Analyzer

	// RedirectDetector detects trailing slash redirects.
	RedirectDetector *RedirectDetector

	// MaxDepth is the maximum discovery depth.
	MaxDepth uint16

	// RequestCache for request-level deduplication.
	// Required - must not be nil.
	RequestCache *reqcache.HMapCache

	// ErrorTracker for consecutive network error detection.
	// If nil, no early exit on network errors.
	ErrorTracker *NetworkErrorTracker

	// WAFBlockTracker for consecutive WAF/CDN block detection.
	// If nil, no early exit on WAF blocks.
	WAFBlockTracker *waf.BlockTracker

	// WAFDetector detects WAF/CDN blocking responses.
	// If nil, WAF detection is disabled.
	WAFDetector waf.Detector

	// CustomHeaders are user-defined HTTP request headers.
	// Applied to every request during discovery.
	CustomHeaders map[string]string

	// JSScan integration for endpoint extraction from JavaScript files.

	// JSScanScanner is the jsscan scanner for JS endpoint extraction.
	// If nil, jsscan is disabled.
	JSScanScanner *jsscan.Scanner

	// JSScanSem is a semaphore to limit concurrent jsscan executions.
	JSScanSem chan struct{}

	// AddExtractedRequest adds an extracted request to the engine's collection.
	// Returns true if the request was new (not a duplicate).
	AddExtractedRequest func(req *jsscan.ExtractedRequest) bool

	// StoreJSScanRequests persists extracted jsscan requests to database.
	// Called after jsscan completes. jsURL is the source JavaScript file.
	StoreJSScanRequests func(jsURL *url.URL, reqs []jsscan.ExtractedRequest)

	// ScopeChecker validates if URLs are within scan scope.
	// Used by redirect handler to filter out-of-scope redirect targets.
	ScopeChecker *scope.Checker
}

// copyBytes creates a copy of a byte slice.
func copyBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// Priority levels (0-11). Lower number = higher priority.
// Pentester perspective: server-leaked data first, then wordlists.
//
// All priorities are centralized here for easy control.
// ModuleTask has dynamic priority from user YAML config.
const (
	// Priority 0: Critical tasks - Spider, JSFetch, CaseSenseDetection.
	PrioritySpider         uint8 = 0
	PriorityJSFetch        uint8 = 0
	PriorityFormSubmission uint8 = 0 // Form submissions from spider

	PriorityJSExtractedRequest uint8 = 1 // JS extracted HTTP requests

	// Priority 1-4: ObservedTask - server-leaked resources (HIGH confidence).
	PriorityObservedFilesNoExt       uint8 = 1
	PriorityObservedFilesCustomExt   uint8 = 2
	PriorityObservedFilesLiteral     uint8 = 2 // Full filenames (e.g., "app.b5ca88ec.js")
	PriorityObservedDirs             uint8 = 2
	PriorityObservedFilesObservedExt uint8 = 3
	PriorityObservedPaths            uint8 = 4

	// Priority 5-6: WordlistTask - short wordlists (fast scan).
	PriorityShortFilesNoExt       uint8 = 5
	PriorityShortFilesCustomExt   uint8 = 6
	PriorityShortDirs             uint8 = 6
	PriorityShortFilesObservedExt uint8 = 6

	// Priority 7: Extension variants and numeric fuzzing.
	PriorityExtensionVariants uint8 = 7
	PriorityNumericFuzz       uint8 = 7

	// Priority 8-11: WordlistTask - long wordlists (thorough scan).
	PriorityLongFilesNoExt       uint8 = 8
	PriorityLongFilesCustomExt   uint8 = 9
	PriorityLongDirs             uint8 = 9
	PriorityLongFilesObservedExt uint8 = 11

	// Priority 10: MalformedPathProbeTask - embedded fuzz.txt per directory.
	PriorityMalformedPathProbe uint8 = 10

	// Priority 12: FuzzTask - custom FUZZ wordlist (runs last).
	PriorityFuzzer uint8 = 12
)
