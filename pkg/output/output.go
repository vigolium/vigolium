package output

import (
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Info contains module metadata
type Info struct {
	Name        string              `json:"name,omitempty"`
	Tags        []string            `json:"tags,omitempty"`
	Description string              `json:"description,omitempty"`
	Reference   []string            `json:"reference,omitempty"`
	Severity    severity.Severity   `json:"severity,omitempty"`
	Confidence  severity.Confidence `json:"confidence,omitempty"`
}

// ResultEvent is a wrapped result event for a single scan output.
// The format is designed to be compatible with Nuclei's JSONL output.
type ResultEvent struct {
	// Module identification (JSON tag kept as "template-id" for Nuclei output compatibility)
	ModuleID string `json:"template-id"`

	// Info contains module metadata, serialized as a nested "info" object
	// (matching Nuclei's JSONL output).
	Info Info `json:"info"`

	// Type is the type of the result event (always "http" for this scanner)
	Type string `json:"type"`

	// Target information
	Host   string `json:"host,omitempty"`
	Scheme string `json:"scheme,omitempty"`
	URL    string `json:"url,omitempty"`
	IP     string `json:"ip,omitempty"`

	// Match details
	Matched          string   `json:"matched-at,omitempty"`
	ExtractedResults []string `json:"extracted-results,omitempty"`
	MatcherStatus    bool     `json:"matcher-status"`

	// Request/Response data
	Request            string   `json:"request,omitempty"`
	Response           string   `json:"response,omitempty"`
	AdditionalEvidence []string `json:"additional_evidence,omitempty"`

	// Metadata
	Metadata  map[string]interface{} `json:"meta,omitempty"`
	Timestamp time.Time              `json:"timestamp"`

	// Fuzzing fields (kept for compatibility with fuzzing results)
	IsFuzzingResult  bool   `json:"is_fuzzing_result,omitempty"`
	FuzzingParameter string `json:"fuzzing_parameter,omitempty"`

	// Error field for error reporting
	Error string `json:"error,omitempty"`

	// Internal fields (not serialized to JSON)
	DisableNotify bool   `json:"-"`
	ModuleType    string `json:"-"`
	FindingSource string `json:"-"`
	ModuleShort   string `json:"-"`
}

// EvidenceSeparator delimits the request and response halves of a single
// evidence entry. The primary Request/Response pair and every AdditionalEvidence
// entry share this format. This is the single source of truth for the delimiter;
// the storage layer's dedup/merge path references it (see pkg/database) so stored
// evidence stays splittable the same way modules emit it.
const EvidenceSeparator = "\n---------\n"

// BuildEvidence renders one request/response pair into a single AdditionalEvidence
// entry. When label is non-empty it is prefixed as a "# [label]" marker line so a
// reviewer — and the UI's evidence tabs — can tell a baseline pair from an attack
// pair from a confirmation round. Returns "" when both halves are empty (so an
// empty pair is never recorded).
func BuildEvidence(label, request, response string) string {
	if request == "" && response == "" {
		return ""
	}
	body := request + EvidenceSeparator + response
	if label == "" {
		return body
	}
	return "# [" + label + "]\n" + body
}

// sha1Pool recycles SHA-1 hashers to avoid allocating one per ResultEvent.ID() call.
var sha1Pool = sync.Pool{
	New: func() interface{} { return sha1.New() },
}

// ID returns a unique identifier for deduplication purposes.
func (r *ResultEvent) ID() string {
	h := sha1Pool.Get().(hash.Hash)
	h.Reset()

	_, _ = io.WriteString(h, r.ModuleID)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, r.Info.Description)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, r.Info.Severity.String())
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, r.Matched)

	var buf [sha1.Size]byte
	id := hex.EncodeToString(h.Sum(buf[:0]))
	sha1Pool.Put(h)
	return id
}

// Writer is an interface which writes output to somewhere for scan events.
type Writer interface {
	// Close closes the output writer interface
	Close()
	// Write writes the event to file and/or screen.
	Write(*ResultEvent) error
	// WriteFileOnly writes the event to file only, skipping screen output.
	WriteFileOnly(*ResultEvent) error
}

// StandardWriter is a writer writing output to file and screen for results.
type StandardWriter struct {
	mutex                   sync.Mutex
	outputFile              io.WriteCloser
	DisableStdout           bool
	IncludeResponseInOutput bool
	JSONOutput              bool
	PhaseTag                string // Phase label for console output prefix (e.g. "scan", "known-issue-scan")
}

func NewStandardWriter(options *types.Options) (*StandardWriter, error) {
	var outputFile io.WriteCloser
	// Create file output for live result streaming during the scan. Skip html
	// (generated post-scan from the database) and deferred jsonl (emitted post-scan
	// as the unified {"type":...,"data":...} envelope — see DeferredJSONLExport).
	liveJSONLFile := options.HasFormat("jsonl") && !options.DeferredJSONLExport
	needsFileOutput := options.Output != "" && (liveJSONLFile || options.HasFormat("console"))
	if needsFileOutput {
		// With a single format, write to the literal -o path. With multiple
		// formats, use the format-specific path so the live file never collides
		// with a post-scan export at the same -o base (e.g. console live file vs
		// the deferred jsonl/html/report files when -o ends in .jsonl/.html).
		filePath := options.Output
		if len(options.OutputFormats) > 1 {
			if liveJSONLFile {
				filePath = options.OutputPathForFormat("jsonl")
			} else {
				filePath = options.OutputPathForFormat("console")
			}
		}
		output, err := newFileOutputWriter(filePath, true)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		outputFile = output
	}

	// Deferred jsonl emits its envelope once the scan finishes, so suppress the
	// live nuclei-style ResultEvent stream on stdout too — unless console output
	// was also requested, which keeps its own live stream. CapturedConsole also
	// keeps the stream alive: the stdout is a captured per-target log file, not a
	// terminal, so the findings belong in it (this is the -P fan-out's child).
	disableStdout := options.Silent
	if options.DeferredJSONLExport && !options.HasFormat("console") && !options.CapturedConsole {
		disableStdout = true
	}

	// CapturedConsole renders the live finding stream in the human-readable
	// console format even when jsonl set JSONOutput: the captured per-target log
	// (the -P fan-out's <output>.console.log) should read like a console scan, not
	// a run of raw JSON objects. The machine-readable form is still in the .jsonl
	// export, written separately post-scan.
	jsonStdout := options.JSONOutput && !options.CapturedConsole

	return &StandardWriter{
		outputFile:              outputFile,
		DisableStdout:           disableStdout,
		IncludeResponseInOutput: options.IncludeResponseInOutput,
		JSONOutput:              jsonStdout,
	}, nil
}

// Write writes the event to file and/or screen.
func (w *StandardWriter) Write(event *ResultEvent) error {
	event.Timestamp = time.Now()

	// Ensure Type is set
	if event.Type == "" {
		event.Type = "http"
	}

	// Ensure MatcherStatus is true for findings
	event.MatcherStatus = true

	var data []byte
	var err error

	data, err = w.formatJSON(event)
	if err != nil {
		return errors.Wrap(err, "could not format output")
	}
	if len(data) == 0 {
		return nil
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if !w.DisableStdout {
		if w.JSONOutput {
			_, _ = os.Stdout.Write(data)
		} else {
			screenData := w.formatScreen(event)
			if len(screenData) > 0 {
				_, _ = os.Stdout.Write(screenData)
				_, _ = os.Stdout.Write([]byte("\n"))
			}
		}
	}

	if w.outputFile != nil {
		if _, writeErr := w.outputFile.Write(data); writeErr != nil {
			return errors.Wrap(err, "could not write to output")
		}
	}
	return nil
}

// WriteFileOnly writes the event to file only, skipping screen output.
func (w *StandardWriter) WriteFileOnly(event *ResultEvent) error {
	event.Timestamp = time.Now()

	if event.Type == "" {
		event.Type = "http"
	}
	event.MatcherStatus = true

	data, err := w.formatJSON(event)
	if err != nil {
		return errors.Wrap(err, "could not format output")
	}
	if len(data) == 0 {
		return nil
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.outputFile != nil {
		if _, writeErr := w.outputFile.Write(data); writeErr != nil {
			return errors.Wrap(writeErr, "could not write to output")
		}
	}
	return nil
}

// Close closes the output writing interface
func (w *StandardWriter) Close() {
	if w.outputFile != nil {
		_ = w.outputFile.Close()
	}
}
