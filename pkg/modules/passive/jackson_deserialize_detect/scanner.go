package jackson_deserialize_detect

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

var (
	// Type discriminator fields in JSON
	typeFieldPattern = regexp.MustCompile(`"@(?:class|type)"\s*:\s*"[a-zA-Z][\w.]*(?:\$[\w]+)*"`)
	// Java class references in JSON values
	javaClassPattern = regexp.MustCompile(`"(?:com|org|net|io|java|javax|jakarta)\.[a-z][\w.]*(?:\$[\w]+)*"`)
	// Jackson/Java deserialization error patterns
	jacksonErrorPattern = regexp.MustCompile(`(?i)(?:com\.fasterxml\.jackson|JsonMappingException|UnrecognizedPropertyException|InvalidTypeIdException|MismatchedInputException|JsonParseException.*type)`)
	deserErrorPattern   = regexp.MustCompile(`(?i)(?:java\.io\.ObjectInputStream|InvalidClassException|StreamCorruptedException|ClassNotFoundException.*deserializ|NotSerializableException)`)
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
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))

	var extracted []string
	detected := false

	// Check JSON responses for type discriminator fields
	if strings.Contains(ct, "json") || strings.Contains(ct, "javascript") {
		if matches := typeFieldPattern.FindAllString(body, 3); len(matches) > 0 {
			detected = true
			for _, match := range matches {
				extracted = append(extracted, "Type field: "+match)
			}
		}

		if matches := javaClassPattern.FindAllString(body, 3); len(matches) > 0 {
			detected = true
			for _, match := range matches {
				extracted = append(extracted, "Java class ref: "+match)
			}
		}
	}

	// Check for deserialization error patterns (any content type)
	if jacksonErrorPattern.MatchString(body) {
		detected = true
		if match := jacksonErrorPattern.FindString(body); match != "" {
			extracted = append(extracted, "Jackson error: "+match)
		}
	}
	if deserErrorPattern.MatchString(body) {
		detected = true
		if match := deserErrorPattern.FindString(body); match != "" {
			extracted = append(extracted, "Deserialization error: "+match)
		}
	}

	if !detected {
		return nil, nil
	}

	sev := severity.Medium
	desc := "Jackson polymorphic typing or Java deserialization indicators detected in response"
	if len(extracted) > 0 && strings.Contains(extracted[0], "Type field") {
		sev = severity.Medium
		desc = "JSON response contains Jackson type discriminator fields (@class/@type), suggesting polymorphic deserialization is enabled which may allow gadget-based attacks"
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Jackson/Java Deserialization Indicators",
				Description: desc,
				Severity:    sev,
				Confidence:  severity.Tentative,
				Tags:        []string{"java", "jackson", "deserialization", "rce-risk"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/502.html"},
			},
		},
	}, nil
}
