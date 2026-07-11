package output

import (
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"strings"
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

// RecordKind separates reconnaissance and unconfirmed hypotheses from
// reportable vulnerabilities while keeping one backward-compatible event shape.
type RecordKind string

const (
	RecordKindFinding     RecordKind = "finding"
	RecordKindCandidate   RecordKind = "candidate"
	RecordKindObservation RecordKind = "observation"
)

// EvidenceGrade records how far a result progressed through confirmation.
type EvidenceGrade string

const (
	EvidenceGradeObservation  EvidenceGrade = "E0"
	EvidenceGradeCandidate    EvidenceGrade = "E1"
	EvidenceGradeDifferential EvidenceGrade = "E2"
	EvidenceGradeBypass       EvidenceGrade = "E3"
	EvidenceGradeImpact       EvidenceGrade = "E4"
)

// ResultEvent is a wrapped result event for a single scan output.
// The format is designed to be compatible with Nuclei's JSONL output.
type ResultEvent struct {
	// Module identification (JSON tag kept as "template-id" for Nuclei output compatibility)
	ModuleID string `json:"template-id"`

	// Info contains module metadata, serialized as a nested "info" object
	// (matching Nuclei's JSONL output).
	Info Info `json:"info"`

	// RecordKind defaults to finding for compatibility with existing modules.
	// Candidate and observation events are persisted but excluded from finding
	// totals, notifications, and cross-module confirmed-result suppression.
	RecordKind    RecordKind    `json:"record_kind,omitempty"`
	EvidenceGrade EvidenceGrade `json:"evidence_grade,omitempty"`

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

	// DedupKey, when non-empty, lets a module choose an explicit deduplication
	// identity instead of the default content hash (module/description/severity/
	// matched): ID() derives the finding's identity from this key alone. Use it when
	// findings should group by something other than their content — e.g. the OAST
	// collector sets the per-payload callback nonce so each distinct callback host is
	// its own finding (callbacks for the same payload coalesce; different payloads
	// stay separate) regardless of the protocol-derived description/severity an
	// upgrade changes. Empty for the default content-based identity.
	DedupKey string `json:"-"`
}

// EffectiveRecordKind returns a validated kind, treating the zero value and
// unknown legacy values as findings.
func (r *ResultEvent) EffectiveRecordKind() RecordKind {
	if r == nil {
		return RecordKindFinding
	}
	switch r.RecordKind {
	case RecordKindObservation, RecordKindCandidate, RecordKindFinding:
		return r.RecordKind
	default:
		return RecordKindFinding
	}
}

// IsFinding reports whether this event is a reportable vulnerability.
func (r *ResultEvent) IsFinding() bool { return r.EffectiveRecordKind() == RecordKindFinding }

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

// EvidencePair is one AdditionalEvidence entry parsed back into structured parts:
// an optional Label plus the Request/Response halves. Prose is set instead (with
// Request/Response empty) when the entry carries no separator — some modules and
// JS extensions push free-form strings into AdditionalEvidence despite the
// documented pair format, so renderers can present real pairs structurally and
// prose as-is rather than guessing.
type EvidencePair struct {
	Label    string
	Request  string
	Response string
	Prose    string
}

// IsPair reports whether the entry parsed as a request/response pair (as opposed
// to a free-form prose entry).
func (e EvidencePair) IsPair() bool { return e.Prose == "" }

// ParseEvidence is the inverse of BuildEvidence: it parses one AdditionalEvidence
// entry back into its structured parts, recognizing the optional "# [label]"
// marker line and the EvidenceSeparator between the request and response halves.
// An entry with no separator is returned as Prose, so a renderer can tell a
// genuine pair from arbitrary text. This is the single parser for the evidence
// format that BuildEvidence produces, so every consumer splits it identically.
func ParseEvidence(entry string) EvidencePair {
	var p EvidencePair
	body := entry
	if strings.HasPrefix(body, "# [") {
		if nl := strings.IndexByte(body, '\n'); nl >= 0 {
			if marker := body[:nl]; strings.HasSuffix(marker, "]") {
				p.Label = marker[len("# [") : len(marker)-1]
				body = body[nl+1:]
			}
		}
	}
	if idx := strings.Index(body, EvidenceSeparator); idx >= 0 {
		p.Request = body[:idx]
		p.Response = body[idx+len(EvidenceSeparator):]
		return p
	}
	p.Prose = body
	return p
}

// sha1Pool recycles SHA-1 hashers to avoid allocating one per ResultEvent.ID() call.
var sha1Pool = sync.Pool{
	New: func() interface{} { return sha1.New() },
}

// ID returns a unique identifier for deduplication purposes. When DedupKey is set
// the identity is derived from it alone (an explicit dedup grouping chosen by the
// producer, e.g. the OAST per-payload nonce); otherwise it is the content hash of
// the module, description, severity, and matched location.
func (r *ResultEvent) ID() string {
	h := sha1Pool.Get().(hash.Hash)
	h.Reset()
	// Preserve historical hashes for default findings. Prefix only non-finding
	// events so a candidate can later be promoted without colliding with itself.
	if kind := r.EffectiveRecordKind(); kind != RecordKindFinding {
		_, _ = io.WriteString(h, string(kind))
		_, _ = io.WriteString(h, "|")
	}

	if r.DedupKey != "" {
		_, _ = io.WriteString(h, "dedup|")
		_, _ = io.WriteString(h, r.DedupKey)
	} else {
		_, _ = io.WriteString(h, r.ModuleID)
		_, _ = io.WriteString(h, "|")
		_, _ = io.WriteString(h, r.Info.Description)
		_, _ = io.WriteString(h, "|")
		_, _ = io.WriteString(h, r.Info.Severity.String())
		_, _ = io.WriteString(h, "|")
		_, _ = io.WriteString(h, r.Matched)
	}

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

	// Only marshal JSON when it is actually consumed: JSON stdout or a live
	// output file. Console-only runs — the common CLI path — render via
	// formatScreen, and would otherwise pay per-event JSON marshaling cost for
	// bytes that are immediately discarded.
	needsJSON := w.JSONOutput || w.outputFile != nil

	var data []byte
	if needsJSON {
		var err error
		data, err = w.formatJSON(event)
		if err != nil {
			return errors.Wrap(err, "could not format output")
		}
		if len(data) == 0 {
			return nil
		}
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
			return errors.Wrap(writeErr, "could not write to output")
		}
	}
	return nil
}

// ShowsFindingsOnStdout reports whether findings passed to Write are rendered to
// stdout in human-readable form during the scan. It's false when stdout is
// suppressed (silent, or a deferred jsonl/html format that emits its output
// post-scan) or when stdout carries raw JSON. Callers use this to decide whether
// to echo a compact human-readable finding line elsewhere (e.g. stderr) so live
// progress stays visible when nothing reaches stdout during the scan.
func (w *StandardWriter) ShowsFindingsOnStdout() bool {
	return !w.DisableStdout && !w.JSONOutput
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
