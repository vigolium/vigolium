package output

import (
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
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

	// Info contains module metadata (inlined in JSON output)
	Info Info `json:"info,inline"`

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
	AdditionalEvidence []string `json:"additional-evidence,omitempty"`

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
	PhaseTag                string // Phase label for console output prefix (e.g. "scan", "spa")
}

func NewStandardWriter(options *types.Options) (*StandardWriter, error) {
	var outputFile io.WriteCloser
	if options.Output != "" && options.OutputFormat != "html" {
		output, err := newFileOutputWriter(options.Output, true)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		outputFile = output
	}

	return &StandardWriter{
		outputFile:              outputFile,
		DisableStdout:           options.Silent,
		IncludeResponseInOutput: options.IncludeResponseInOutput,
		JSONOutput:              options.JSONOutput,
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
