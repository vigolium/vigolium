package graphql_introspection_detect

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// Primary introspection markers — at least one must be present.
var primaryMarkers = []string{"\"__schema\"", "\"__type\""}

// Confirmation markers — at least one must accompany a primary marker.
var confirmationMarkers = []string{"\"queryType\"", "\"mutationType\"", "\"subscriptionType\"", "\"types\""}

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
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	// Check for primary markers
	var foundPrimary []string
	for _, marker := range primaryMarkers {
		if strings.Contains(body, marker) {
			foundPrimary = append(foundPrimary, marker)
		}
	}
	if len(foundPrimary) == 0 {
		return nil, nil
	}

	// Require at least one confirmation marker to avoid FPs
	var foundConfirmation []string
	for _, marker := range confirmationMarkers {
		if strings.Contains(body, marker) {
			foundConfirmation = append(foundConfirmation, marker)
		}
	}
	if len(foundConfirmation) == 0 {
		return nil, nil
	}

	extracted := make([]string, 0, len(foundPrimary)+len(foundConfirmation))
	for _, p := range foundPrimary {
		extracted = append(extracted, fmt.Sprintf("Primary: %s", p))
	}
	for _, c := range foundConfirmation {
		extracted = append(extracted, fmt.Sprintf("Confirmation: %s", c))
	}

	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			Request:  string(ctx.Request().Raw()),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "GraphQL Introspection Enabled",
				Description: fmt.Sprintf("GraphQL introspection response detected with %d schema markers", len(foundPrimary)+len(foundConfirmation)),
			},
		},
	}, nil
}
