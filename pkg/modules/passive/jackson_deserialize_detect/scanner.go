package jackson_deserialize_detect

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var (
	// Java class references in JSON values
	javaClassPattern = regexp.MustCompile(`"(?:com|org|net|io|java|javax|jakarta)\.[a-z][\w.]*(?:\$[\w]+)*"`)
	// Jackson/Java deserialization error patterns
	jacksonErrorPattern   = regexp.MustCompile(`(?i)(?:com\.fasterxml\.jackson|JsonMappingException|UnrecognizedPropertyException|InvalidTypeIdException|MismatchedInputException|JsonParseException.*type)`)
	deserErrorPattern     = regexp.MustCompile(`(?i)(?:java\.io\.ObjectInputStream|InvalidClassException|StreamCorruptedException|ClassNotFoundException.*deserializ|NotSerializableException)`)
	jacksonContextPattern = regexp.MustCompile(`(?i)(?:cannot deserialize|through reference chain|at \[Source:|line:\s*\d+|column:\s*\d+|com\.fasterxml\.jackson\.databind)`)
	deserContextPattern   = regexp.MustCompile(`(?i)(?:readObject|serialVersionUID|stream header|local class incompatible|object input stream|deserializ)`)
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("jackson_deserialize_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	// Static assets (minified JS bundles especially) are full of reverse-DNS
	// identifiers like "io.foo"/"com.app.title" and stray Java-sounding strings.
	// A deserialization indicator inside such an asset is not a live signal, so
	// skip them outright rather than substring-matching them.
	if modkit.IsStaticAssetContentType(ct) || modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	var extracted []string
	var typeFields []string

	// Parse actual JSON keys rather than matching source text or quoted examples.
	if strings.Contains(ct, "json") {
		typeFields = findTypeDiscriminators(body)
		for _, match := range typeFields {
			extracted = append(extracted, "Type discriminator: "+match)
		}
	}

	status := ctx.Response().StatusCode()
	isErrorStatus := status >= 400 && status <= 599
	jacksonError := jacksonErrorPattern.MatchString(body)
	javaDeserError := deserErrorPattern.MatchString(body)
	corroboratedError := false
	if jacksonError {
		if match := jacksonErrorPattern.FindString(body); match != "" {
			extracted = append(extracted, "Jackson error marker: "+match)
		}
		if context := jacksonContextPattern.FindString(body); context != "" {
			extracted = append(extracted, "Jackson error context: "+context)
			corroboratedError = isErrorStatus
		}
	}
	if javaDeserError {
		if match := deserErrorPattern.FindString(body); match != "" {
			extracted = append(extracted, "Deserialization error marker: "+match)
		}
		if context := deserContextPattern.FindString(body); context != "" {
			extracted = append(extracted, "Deserialization error context: "+context)
			corroboratedError = isErrorStatus
		}
	}

	if len(typeFields) == 0 && !jacksonError && !javaDeserError {
		return nil, nil
	}

	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	desc := "The response contains Jackson/Java serialization metadata or a single error marker. This is implementation context; attacker-controlled input deserialization was not established."
	if len(typeFields) > 0 {
		sev = severity.Low
		desc = "Parsed JSON contains @class/@type values naming Java classes. This proves response-side type metadata, not that arbitrary attacker-selected classes are accepted on input."
	}
	if corroboratedError {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		sev = severity.Low
		desc = "An HTTP error response contains independent Jackson/Java deserialization anchors. This supports an input-processing candidate, but no attacker-selected type, gadget reachability, side effect, or code execution was demonstrated."
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       kind,
			EvidenceGrade:    grade,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Jackson/Java Deserialization Indicators",
				Description: desc,
				Severity:    sev,
				Confidence:  severity.Tentative,
				Tags:        []string{"java", "jackson", "deserialization", "rce-risk"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/502.html"},
			},
			Metadata: map[string]any{
				"status_code":                status,
				"type_discriminator_count":   len(typeFields),
				"corroborated_error":         corroboratedError,
				"attacker_type_tested":       false,
				"gadget_reachability_tested": false,
				"code_execution_tested":      false,
			},
		},
	}, nil
}

func findTypeDiscriminators(body string) []string {
	var document any
	if json.Unmarshal([]byte(body), &document) != nil {
		return nil
	}
	seen := make(map[string]bool)
	var walk func(any)
	walk = func(node any) {
		switch typed := node.(type) {
		case map[string]any:
			for key, value := range typed {
				if key == "@class" || key == "@type" {
					if className, ok := value.(string); ok && javaClassPattern.MatchString(`"`+className+`"`) {
						seen[key+"="+className] = true
					}
				}
				walk(value)
			}
		case []any:
			for _, value := range typed {
				walk(value)
			}
		}
	}
	walk(document)
	results := make([]string, 0, len(seen))
	for value := range seen {
		results = append(results, value)
	}
	sort.Strings(results)
	return results
}
