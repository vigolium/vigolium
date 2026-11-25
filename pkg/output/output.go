package output

import (
	"crypto/sha1"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/terminal"
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
//
// Its JSON tags (template-id, matched-at, info{}) are an IMPORT and LEGACY
// format: `finding load` accepts them, and --ci-output-format still prints them
// this release. No -j document carries them — a machine reads findings in the
// finding-view shape (pkg/cli findingViewFromEvent / compactFindingView).
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

	// Replay context, set by the executor so `finding verify` can re-run the
	// module exactly: OriginRecordUUID is the http_record of the item the
	// module scanned (empty when the run stores nothing), InsertionPointType
	// names the point it mutated (an httpmsg.InsertionPointType.String() value;
	// the point's name is FuzzingParameter), and Payload is the value it
	// injected there. Persisted as findings.origin_record_uuid,
	// insertion_point and payload.
	OriginRecordUUID   string `json:"origin_record_uuid,omitempty"`
	InsertionPointType string `json:"insertion_point_type,omitempty"`
	Payload            string `json:"payload,omitempty"`

	// Proof is the module's decision as a recipe a caller re-runs itself
	// (proof.go); nil for a module that has not opted in. Persisted as
	// findings.proof.
	Proof *ProofRecipe `json:"proof,omitempty"`

	// Error field for error reporting
	Error string `json:"error,omitempty"`

	// VulnClass is the reported vulnerability class (a pkg/vulnclass name)
	// when the result itself decides it: an OAST callback reports the class
	// its payload was minted for, which a multi-class module (oast-probe)
	// cannot declare once. Empty means the module's declared class applies.
	VulnClass string `json:"vuln_class,omitempty"`

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

	// BaseURL is the URL of the unmutated item the module scanned, stamped by
	// the executor. It is the location of a v2 identity (IdentityKey), so a
	// payload in the path or query never changes a finding's identity.
	BaseURL string `json:"-"`
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

// ID returns the finding's identity hash: the SHA-1 of IdentityKey(). See
// identity.go for what identifies a finding.
func (r *ResultEvent) ID() string {
	return HashIdentity(r.IdentityKey())
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
	// PlainLines renders each finding on stdout as one uncoloured screen line
	// with no phase prefix (--silent).
	PlainLines bool
	PhaseTag   string // Phase label for console output prefix (e.g. "scan", "known-issue-scan")
	// OnEvent, when set, is invoked for every finding this writer emits, before
	// any rendering. It exists so a single seam can observe the whole finding
	// stream — the machine event stream (--events) counts and reports findings
	// through it — instead of each of the runner's ~six OnResult callbacks
	// growing its own copy, which is how one of them ends up missed.
	//
	// It runs on the emitting goroutine BEFORE the writer takes its mutex, so it
	// is NOT serialized against other writers — a hook must be concurrency-safe
	// on its own, cheap, and must not call back into the writer. (Calling it
	// under the lock would put a stdout write inside the writer's mutex.)
	OnEvent func(*ResultEvent)
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
	// --events owns stdout outright. Its whole contract is that a consumer can
	// pipe stdout through a JSON parser and see nothing else, so a human finding
	// line landing there would break every line-oriented reader on the first
	// finding. The render is not lost: with stdout suppressed, ShowsFindingsOnStdout
	// goes false and the runner's echoLiveFinding puts the same line on stderr,
	// where the rest of the console already lives.
	// -j reserves stdout for the scan document written after the run, under the
	// same rule: one protocol on stdout, the live render on stderr.
	if options.Events != "" || options.StdoutDocument {
		disableStdout = true
	}
	// --format github without -o writes its workflow commands to stdout after
	// the scan; the live finding lines go to stderr instead (as under --events),
	// so the annotations are the only thing on stdout.
	if options.HasFormat("github") && options.Output == "" {
		disableStdout = true
	}

	// --silent: one plain line per finding, and stdout is otherwise silent.
	// The CLI sets it only when nothing else owns stdout (-j, --events, a
	// stdout jsonl or github stream).
	plainLines := options.FindingLinesToStdout
	if plainLines {
		disableStdout = false
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
		JSONOutput:              jsonStdout && !plainLines,
		PlainLines:              plainLines,
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

	if w.OnEvent != nil {
		w.OnEvent(event)
	}

	// Only marshal JSON when it is actually consumed: JSON stdout or a live
	// output file. Console-only runs — the common CLI path — render via
	// formatScreen, and would otherwise pay per-event JSON marshaling cost for
	// bytes that are immediately discarded.
	//
	// JSONOutput alone is not a consumer: the deferred formats (jsonl, html) set
	// it while suppressing live stdout and writing the real artifact at the end
	// from stored findings. Such a run has no live sink at all, so without the
	// DisableStdout term every finding was marshaled — request, response and all
	// the evidence — straight into the discard below.
	needsJSON := (w.JSONOutput && !w.DisableStdout) || w.outputFile != nil

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
		} else if w.PlainLines {
			_, _ = os.Stdout.WriteString(FormatFindingLine(event) + "\n")
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

// FormatFindingLine is the --silent finding line: the console's screen line
// with no phase prefix and no color.
func FormatFindingLine(event *ResultEvent) string {
	w := &StandardWriter{}
	return strings.TrimRight(terminal.StripANSI(string(w.formatScreen(event))), "\n")
}

// WriteFileOnly writes the event to file only, skipping screen output.
func (w *StandardWriter) WriteFileOnly(event *ResultEvent) error {
	event.Timestamp = time.Now()

	if event.Type == "" {
		event.Type = "http"
	}
	event.MatcherStatus = true

	// The file is the only sink here, so no file means nothing to serialize.
	// Checked before marshaling rather than after: the encode is the expensive
	// half, and on a run configured without a live output file every finding was
	// paying it for bytes that were never written anywhere. outputFile is set at
	// construction and never cleared, so one check is enough.
	if w.outputFile == nil {
		return nil
	}

	data, err := w.formatJSON(event)
	if err != nil {
		return errors.Wrap(err, "could not format output")
	}
	if len(data) == 0 {
		return nil
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if _, writeErr := w.outputFile.Write(data); writeErr != nil {
		return errors.Wrap(writeErr, "could not write to output")
	}
	return nil
}

// Close closes the output writing interface
func (w *StandardWriter) Close() {
	if w.outputFile != nil {
		_ = w.outputFile.Close()
	}
}
