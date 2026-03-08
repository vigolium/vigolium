package sql_syntax_detect

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// SQL detection patterns.
var (
	// sqlStatementRe matches full SQL statements in parameter values.
	sqlStatementRe = regexp.MustCompile(`(?i)\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM|UNION\s+(?:ALL\s+)?SELECT|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|EXEC(?:\s+|\()|HAVING\s+\d|ORDER\s+BY\s+\d|GROUP\s+BY\s+\d)`)

	// sqlKeywordPairRe matches SQL keyword pairs that suggest SQL fragments.
	sqlKeywordPairRe = regexp.MustCompile(`(?i)\b(?:WHERE|AND|OR)\s+[\w.]+\s*(?:=|<|>|LIKE|IN\s*\(|BETWEEN|IS\s+NULL)`)
)

// minValueLen is the minimum parameter value length to check (reduces false positives).
const minValueLen = 8

// Module implements the SQL Syntax Detection passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new SQL Syntax Detection module.
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
			modkit.PassiveScanScopeRequest,
		),
		rhm: dedup.LazyDefaultRHM("passive_sql_syntax_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest checks request parameters for SQL syntax patterns.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	params, err := ctx.Request().Parameters()
	if err != nil || len(params) == 0 {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent
	for _, param := range params {
		value := param.Value()
		if len(value) < minValueLen {
			continue
		}

		// URL-decode the value since SQL in params is often encoded
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			decoded = value
		}

		matched := matchSQL(decoded)
		if matched == "" {
			continue
		}

		if rhm != nil && !rhm.ShouldCheck3(urlx, ctx.Request().Method(), ctx.Request().BodyToString(), param.Name(), "", "sql") {
			continue
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			FuzzingParameter: param.Name(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: []string{
				fmt.Sprintf("Parameter: %s", param.Name()),
				fmt.Sprintf("SQL pattern: %s", matched),
				fmt.Sprintf("Value (truncated): %s", truncate(decoded, 120)),
			},
			Info: output.Info{
				Name:        "SQL Syntax in Request Parameter",
				Description: fmt.Sprintf("Parameter %q contains SQL syntax: %s", param.Name(), matched),
			},
		})
	}

	return results, nil
}

// matchSQL checks if a value contains SQL syntax and returns the matched pattern.
func matchSQL(value string) string {
	if match := sqlStatementRe.FindString(value); match != "" {
		return match
	}
	if match := sqlKeywordPairRe.FindString(value); match != "" {
		return match
	}
	return ""
}

// truncate returns the first n characters of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
