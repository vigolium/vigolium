package insecure_deserialization

import (
	"fmt"
	"regexp"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// deserError defines a deserialization error pattern.
type deserError struct {
	framework string
	pattern   *regexp.Regexp
}

var errorPatterns = []deserError{
	{"Java", regexp.MustCompile(`(?i)(?:java\.io\.ObjectInputStream|java\.io\.InvalidClassException|java\.lang\.ClassCastException.*deserializ|ClassNotFoundException.*deserializ|InvalidObjectException|StreamCorruptedException)`)},
	{"Java", regexp.MustCompile(`(?i)(?:org\.apache\.commons\.collections\.functors|com\.sun\.org\.apache\.xalan|ysoserial|CommonsCollections)`)},
	{"PHP", regexp.MustCompile(`(?i)(?:unserialize\(\)|O:\d+:"[^"]+"|PHP Fatal error.*unserialize|__wakeup|__destruct.*called)`)},
	{"Python", regexp.MustCompile(`(?i)(?:pickle\.loads|cPickle\.loads|_pickle\.UnpicklingError|yaml\.load|yaml\.unsafe_load)`)},
	{"Ruby", regexp.MustCompile(`(?i)(?:Marshal\.load|YAML\.load|Psych::DisallowedClass|ERB.*new.*result|Gem::Installer)`)},
	{".NET", regexp.MustCompile(`(?i)(?:System\.Runtime\.Serialization|BinaryFormatter|SoapFormatter|ObjectStateFormatter|LosFormatter|NetDataContractSerializer|TypeNameHandling)`)},
	{"Java", regexp.MustCompile(`(?i)(?:org\.apache\.commons\.beanutils|com\.sun\.rowset\.JdbcRowSetImpl|org\.hibernate\..*Exception|org\.springframework\..*SerializationException)`)},
}

// deserPayload defines a deserialization probe.
type deserPayload struct {
	payload string
	desc    string
}

var payloads = []deserPayload{
	{
		// Java serialized object magic bytes (base64 of 0xACED0005)
		payload: "\xac\xed\x00\x05sr\x00\x01A",
		desc:    "Java serialization magic bytes",
	},
	{
		payload: `O:8:"stdClass":0:{}`,
		desc:    "PHP serialize format",
	},
	{
		payload: `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"}`,
		desc:    ".NET TypeNameHandling probe",
	},
	{
		payload: "!!python/object/apply:os.system ['id']",
		desc:    "Python YAML deserialization",
	},
	{
		payload: "\x04\x08o:\x30ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy",
		desc:    "Ruby Marshal.load probe",
	},
	{
		payload: `{"$type":"System.Windows.Forms.AxHost+State, System.Windows.Forms"}`,
		desc:    ".NET AxHost State deserialization",
	},
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

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Get original response body to filter false positives
	var origBody string
	if ctx.Response() != nil {
		origBody = ctx.Response().BodyToString()
	}

	var results []*output.ResultEvent

	for _, p := range payloads {
		fuzzedRaw := ip.BuildRequest([]byte(p.payload))

		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		body := resp.Body().String()
		if framework, matched := checkDeserError(body, origBody); matched {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.FullResponse().String(),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{p.payload, p.desc},
				Info: output.Info{
					Description: fmt.Sprintf("Framework: %s — %s", framework, p.desc),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// checkDeserError checks if response contains deserialization error patterns not in original.
func checkDeserError(body, origBody string) (string, bool) {
	for _, ep := range errorPatterns {
		if ep.pattern.MatchString(body) {
			if origBody != "" && ep.pattern.MatchString(origBody) {
				continue
			}
			return ep.framework, true
		}
	}
	return "", false
}
