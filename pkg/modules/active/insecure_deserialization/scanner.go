package insecure_deserialization

import (
	"fmt"
	"regexp"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// deserError defines a deserialization error pattern.
type deserError struct {
	framework string
	pattern   *regexp.Regexp
}

// errorPatterns are framework deserialization-error signatures. The two-anchor
// forms below (X ... Y) deliberately bound the gap between the anchors:
// unbounded ".*" filler lets a lazy match bridge two coincidental words tens of
// KB apart in a large single-line body (the classic "Oracle.*?Driver spanned a
// Salesforce Aura app shell" false positive), and a Java FQCN filler is further
// constrained to package-name characters ([\w.$]) so it cannot cross JSON/HTML
// structure. A genuine leak names the class in one compact phrase, so the bounds
// never clip a true positive. The general match-span guard in checkDeserError is
// the backstop for any signature that still matches too wide.
var errorPatterns = []deserError{
	{"Java", regexp.MustCompile(`(?i)(?:java\.io\.ObjectInputStream|java\.io\.InvalidClassException|java\.lang\.ClassCastException.{0,80}deserializ|ClassNotFoundException.{0,80}deserializ|InvalidObjectException|StreamCorruptedException)`)},
	{"Java", regexp.MustCompile(`(?i)(?:org\.apache\.commons\.collections\.functors|com\.sun\.org\.apache\.xalan|ysoserial|CommonsCollections)`)},
	{"PHP", regexp.MustCompile(`(?i)(?:unserialize\(\)|O:\d+:"[^"]+"|PHP Fatal error.{0,80}unserialize|__wakeup|__destruct.{0,40}called)`)},
	{"Python", regexp.MustCompile(`(?i)(?:pickle\.loads|cPickle\.loads|_pickle\.UnpicklingError|yaml\.load|yaml\.unsafe_load)`)},
	{"Ruby", regexp.MustCompile(`(?i)(?:Marshal\.load|YAML\.load|Psych::DisallowedClass|ERB\.{0,20}new.{0,80}result|Gem::Installer)`)},
	{".NET", regexp.MustCompile(`(?i)(?:System\.Runtime\.Serialization|BinaryFormatter|SoapFormatter|ObjectStateFormatter|LosFormatter|NetDataContractSerializer|TypeNameHandling)`)},
	{"Java", regexp.MustCompile(`(?i)(?:org\.apache\.commons\.beanutils|com\.sun\.rowset\.JdbcRowSetImpl|org\.hibernate\.[\w.$]{0,80}Exception|org\.springframework\.[\w.$]{0,80}SerializationException)`)},
}

// deserPayload defines a deserialization probe.
type deserPayload struct {
	framework string
	payload   string
	desc      string
}

var payloads = []deserPayload{
	{
		framework: "Java",
		// Java serialized object magic bytes (base64 of 0xACED0005)
		payload: "\xac\xed\x00\x05sr\x00\x01A",
		desc:    "Java serialization magic bytes",
	},
	{
		framework: "PHP",
		payload:   `O:8:"stdClass":0:{}`,
		desc:      "PHP serialize format",
	},
	{
		framework: ".NET",
		payload:   `{"$type":"Vigolium.Probe.DoesNotExist, VigoliumProbe"}`,
		desc:      ".NET nonexistent-type probe",
	},
	{
		framework: "Python",
		payload:   "!!python/object:vigolium.Probe {}",
		desc:      "Python YAML nonexistent-object probe",
	},
	{
		framework: "Ruby",
		payload:   "\x04\x08o:\x13Vigolium::Probe\x00",
		desc:      "Ruby Marshal nonexistent-class probe",
	},
	{
		framework: ".NET",
		payload:   `{"$type":"Vigolium.SecondProbe.DoesNotExist, VigoliumProbe"}`,
		desc:      ".NET secondary nonexistent-type probe",
	},
}

type probeCapture struct {
	body         string
	request      string
	response     string
	status       int
	blocked      bool
	errorSurface bool
}

// Module implements the Insecure Deserialization active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Insecure Deserialization module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeInsertionPoint,
			modkit.BodyParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("insecure_deserialization"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for deserialization vulnerabilities.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if scanCtx != nil {
		rhm := m.rhm.Get(scanCtx.DedupMgr())
		if rhm != nil {
			paramName := ip.Name()
			paramType := fmt.Sprintf("%d", ip.Type())
			if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
				return nil, nil
			}
		}
	}

	// Get original response body to filter false positives
	var origBody string
	if ctx.Response() != nil {
		origBody = ctx.Response().BodyToString()
	}

	controlValue := "vigolium_plain_" + modkit.FreshCanary()
	controlRaw := ip.BuildRequest([]byte(controlValue))
	control, err := m.executeProbe(ctx, httpClient, controlRaw)
	if err != nil || control.status == 0 || control.blocked {
		return nil, nil
	}
	if _, noisy := checkDeserError(control.body, origBody, controlValue); noisy {
		return nil, nil
	}

	for _, p := range payloads {
		fuzzedRaw := ip.BuildRequest([]byte(p.payload))
		first, err := m.executeProbe(ctx, httpClient, fuzzedRaw)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}
		if first.blocked || !first.errorSurface {
			continue
		}
		framework, matched := checkDeserError(first.body, origBody, p.payload)
		if !matched || framework != p.framework {
			continue
		}

		second, replayErr := m.executeProbe(ctx, httpClient, fuzzedRaw)
		if replayErr != nil || second.blocked || !second.errorSurface {
			continue
		}
		replayedFramework, replayed := checkDeserError(second.body, origBody, p.payload)
		if !replayed || replayedFramework != p.framework {
			continue
		}

		return []*output.ResultEvent{{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeDifferential,
			URL:           urlx.String(),
			Matched:       urlx.String(),
			Request:       first.request,
			Response:      first.response,
			AdditionalEvidence: []string{
				output.BuildEvidence("benign malformed-value control", control.request, control.response),
				output.BuildEvidence("serialized probe replay", second.request, second.response),
			},
			FuzzingParameter: ip.Name(),
			ExtractedResults: []string{
				"Framework: " + framework,
				"Probe: " + p.desc,
				"Payload-specific error reproduced twice; plain control stayed clean",
			},
			Info: output.Info{
				Name:        "Server-Side Deserialization Reachability Candidate",
				Description: fmt.Sprintf("The %s probe reproducibly introduced a %s deserialization exception while a plain malformed-value control stayed clean. This strongly indicates attacker input reaches a deserializer, but no gadget execution, side effect, or code execution was demonstrated.", p.desc, framework),
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        ModuleTags,
			},
			Metadata: map[string]any{
				"framework":             framework,
				"payload_specific":      true,
				"confirmation_rounds":   2,
				"benign_control_clean":  true,
				"gadget_execution":      false,
				"side_effect_confirmed": false,
			},
		}}, nil
	}

	return nil, nil
}

func (m *Module) executeProbe(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (probeCapture, error) {
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return probeCapture{}, err
	}
	defer resp.Close()
	if resp.Response() == nil {
		return probeCapture{}, nil
	}
	return probeCapture{
		body:         resp.BodyString(),
		request:      string(raw),
		response:     resp.FullResponseString(),
		status:       resp.Response().StatusCode,
		blocked:      infra.IsBlockedResponse(resp),
		errorSurface: infra.IsErrorSurfaceStatus(resp),
	}, nil
}

// checkDeserError reports whether the response surfaced a framework
// deserialization error signature that is ABSENT from the baseline.
//
// The injected payload is stripped (modkit.StripReflected) before matching:
// several serialized wire formats are themselves matched by the framework error
// patterns — most notably PHP's O:N:"class":... form, which satisfies the
// `O:\d+:"[^"]+"` alternative — so an endpoint that merely REFLECTS the rejected
// payload back in an error or echo (e.g. `invalid input: O:8:"stdClass":0:{}`)
// would otherwise self-trigger a High/Firm finding without ever deserializing
// anything. Removing the reflected payload first leaves only server-emitted text,
// so a genuine unserialize() / __wakeup() / ObjectInputStream signature still
// matches while a bare echo of our own probe does not. (An error that quotes the
// payload amid a real signature — `unserialize(): Error ... O:8:"stdClass":0:{}` —
// still matches on the surviving `unserialize()` keyword.)
func checkDeserError(body, origBody, payload string) (string, bool) {
	body = modkit.StripReflected(body, payload)
	for _, ep := range errorPatterns {
		// Accept only a plausibly compact signature span (the shared error-based
		// guard), so a two-anchor pattern whose filler bridged unrelated content on
		// a large body is not read as a leak.
		if !modkit.MatchWithinSpan(ep.pattern, body, modkit.MaxErrorSignatureSpan) {
			continue
		}
		if origBody != "" && ep.pattern.MatchString(origBody) {
			continue
		}
		return ep.framework, true
	}
	return "", false
}
