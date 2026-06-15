package password_autocomplete_detect

import (
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

var passwordInputRe = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']?password["']?[^>]*>`)

// autocompleteOffRe matches autocomplete="off" or autocomplete="new-password" in a tag.
var autocompleteOffRe = regexp.MustCompile(`(?i)autocomplete\s*=\s*["']?(off|new-password)["']?`)

// formAutocompleteRe extracts form tags with their attributes.
var formAutocompleteRe = regexp.MustCompile(`(?i)<form[^>]*autocomplete\s*=\s*["']?off["']?[^>]*>`)

// Module implements the Password Autocomplete Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Password Autocomplete Detect module.
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
		ds: dedup.LazyDiskSet("passive_password_autocomplete_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// RequiredContentClasses gates this module to HTML responses. It inspects
// <form>/<input> autocomplete markup that cannot exist in a JSON/XML body, so
// the executor skips it on confirmed non-HTML responses (it still runs on
// unknown/text responses — see modkit.ContentClassAllows).
func (m *Module) RequiredContentClasses() []string { return []string{"html"} }

// ScanPerRequest checks HTML responses for password fields without autocomplete disabled.
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

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(urlx.Host + urlx.Path)
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	matches := passwordInputRe.FindAllString(body, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	// Check if the form has autocomplete=off globally
	formHasOff := formAutocompleteRe.MatchString(body)

	var vulnerable []string
	for _, tag := range matches {
		if autocompleteOffRe.MatchString(tag) {
			continue
		}
		if formHasOff {
			continue
		}
		vulnerable = append(vulnerable, tag)
	}

	if len(vulnerable) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:             urlx.Host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: vulnerable,
			Info: output.Info{
				Description: "Password field(s) without autocomplete disabled",
			},
		},
	}, nil
}
