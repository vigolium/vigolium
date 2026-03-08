package input_reflection_detect

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// allNumericRe matches values that are entirely digits.
var allNumericRe = regexp.MustCompile(`^\d+$`)

// tokenLikeRe matches values that look like tokens/hashes (hex or base64-ish, 20+ chars).
var tokenLikeRe = regexp.MustCompile(`^[a-fA-F0-9]{20,}$|^[a-zA-Z0-9+/=]{20,}$`)

// Module implements the Input Reflection Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Input Reflection Detect module.
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
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("passive_input_reflection_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest checks if request parameter values are reflected in the response.
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

	params, err := ctx.Request().Parameters()
	if err != nil || len(params) == 0 {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	var reflected []string
	for _, p := range params {
		val := p.Value()

		// Filter out uninteresting values
		if len(val) < 4 || len(val) > 200 {
			continue
		}
		if allNumericRe.MatchString(val) {
			continue
		}
		if tokenLikeRe.MatchString(val) {
			continue
		}

		// Dedup by host+path+paramName
		dedupKey := utils.Sha1(fmt.Sprintf("%s%s%s", urlx.Host, urlx.Path, p.Name()))
		if diskSet != nil && diskSet.IsSeen(dedupKey) {
			continue
		}

		if strings.Contains(body, val) {
			reflected = append(reflected, fmt.Sprintf("%s=%s", p.Name(), val))
		}
	}

	if len(reflected) == 0 {
		return nil, nil
	}

	// Annotate record with semantic tag
	if scanCtx != nil && scanCtx.RemarksAnnotator != nil && scanCtx.RequestUUIDResolver != nil {
		uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(ctx.Request().ID())
		if uuid != "" {
			if err := scanCtx.RemarksAnnotator.AppendRemarks(context.Background(), map[string][]string{uuid: {"reflects-input"}}); err != nil {
				zap.L().Debug("input_reflection_detect: failed to annotate", zap.Error(err))
			}
		}
	}

	return []*output.ResultEvent{
		{
			Host:             urlx.Host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: reflected,
			Info: output.Info{
				Description: fmt.Sprintf("Found %d reflected parameter(s) in response", len(reflected)),
			},
		},
	}, nil
}
