package graphql_introspection_detect

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the GraphQL Introspection Leak Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new GraphQL Introspection Leak Detect module.
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
		ds: dedup.LazyDiskSet("passive_graphql_introspection_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response for GraphQL introspection data.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Only inspect JSON responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "json") {
		return nil, nil
	}

	// Dedup on host+path
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	kind, extracted, ok := parseIntrospectionResponse(body)
	if !ok {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       output.RecordKindObservation,
			EvidenceGrade:    output.EvidenceGradeObservation,
			DedupKey:         fmt.Sprintf("graphql-introspection|%s|%s", urlx.Host, urlx.Path),
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "GraphQL Introspection Schema Observed",
				Description: fmt.Sprintf("A structurally valid GraphQL %s introspection response is present. Public schema discovery is supported behavior and does not prove unauthorized resolver access.", kind),
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        ModuleTags,
			},
			Metadata: map[string]any{
				"introspection_kind":       kind,
				"authorization_bypassed":   false,
				"sensitive_data_confirmed": false,
			},
		},
	}, nil
}

func parseIntrospectionResponse(body string) (string, []string, bool) {
	var envelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil || len(envelope.Data) == 0 {
		return "", nil, false
	}
	if raw := envelope.Data["__schema"]; len(raw) > 0 {
		var schema struct {
			QueryType        map[string]any   `json:"queryType"`
			MutationType     map[string]any   `json:"mutationType"`
			SubscriptionType map[string]any   `json:"subscriptionType"`
			Types            []map[string]any `json:"types"`
		}
		if json.Unmarshal(raw, &schema) == nil && (len(schema.QueryType) > 0 || len(schema.Types) > 0) {
			extracted := []string{fmt.Sprintf("types=%d", len(schema.Types))}
			if name, _ := schema.QueryType["name"].(string); name != "" {
				extracted = append(extracted, "queryType="+name)
			}
			return "schema", extracted, true
		}
	}
	if raw := envelope.Data["__type"]; len(raw) > 0 {
		var typeInfo struct {
			Name        string           `json:"name"`
			Fields      []map[string]any `json:"fields"`
			InputFields []map[string]any `json:"inputFields"`
		}
		if json.Unmarshal(raw, &typeInfo) == nil && typeInfo.Name != "" && (typeInfo.Fields != nil || typeInfo.InputFields != nil) {
			return "type", []string{"type=" + typeInfo.Name, fmt.Sprintf("fields=%d", len(typeInfo.Fields)+len(typeInfo.InputFields))}, true
		}
	}
	return "", nil, false
}
