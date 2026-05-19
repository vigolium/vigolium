package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// oastMintPerRunCap bounds canary minting. A handful of blind-class probes
// per surface is normal; well past that the agent is almost certainly
// spraying rather than reasoning.
const oastMintPerRunCap = 50

// NewOASTMintTool returns the oast_mint tool. The interactsh Service is
// lazy-owned by autopilot: it isn't created until the agent actually mints a
// canary (zero polling cost on runs that never blind-test), and the caller
// must defer Shutdown() so late callbacks get a grace window before the
// client deregisters. Pairs with the existing oast_poll tool — mint returns
// the nonce, poll reads interactions back by it.
func NewOASTMintTool(ctx *ScanContext) *OASTMintTool {
	return &OASTMintTool{ctx: ctx}
}

// OASTMintTool is exported (unlike sibling tools) so autopilot.Run can hold a
// typed handle for the deferred Shutdown — tool.Tool has no teardown hook.
type OASTMintTool struct {
	ctx *ScanContext

	once        sync.Once
	svc         *oast.Service
	unavailable string // set during once.Do when OAST can't be brought up

	shutdownOnce sync.Once
	count        atomic.Int64
}

func (*OASTMintTool) Name() string     { return "oast_mint" }
func (*OASTMintTool) Label() string    { return "Mint OAST canary" }
func (*OASTMintTool) Category() string { return tool.CategoryVigolium }
func (*OASTMintTool) IsReadOnly() bool { return false }
func (*OASTMintTool) Description() string {
	return "Mint a fresh out-of-band (OAST) canary URL to embed in a hand-crafted blind payload " +
		"(blind SSRF / RCE / XXE / blind SQLi) sent via replay_request, send_raw_http, or web_fetch. " +
		"Returns the callback URL plus the nonce to poll by. After firing the payload, call oast_poll " +
		"with search=<nonce> to see if the target called back. Capped at 50 mints per run."
}

func (*OASTMintTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"target_url": map[string]any{
				"type":        "string",
				"description": "Optional: the URL/endpoint you're injecting into. Recorded for correlation when the callback lands.",
			},
			"param": map[string]any{
				"type":        "string",
				"description": "Optional: the parameter/header name carrying the payload. Recorded for correlation.",
			},
			"kind": map[string]any{
				"type":        "string",
				"description": "Optional injection class label (e.g. 'ssrf', 'rce', 'xxe', 'sqli') — informational, surfaced on the correlated interaction.",
			},
		},
	}
}

func (t *OASTMintTool) Execute(_ context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if t.ctx == nil {
		return tool.Result{Content: "oast_mint unavailable: no scan context configured", IsError: true}, nil
	}
	if res, ok := requireRepo(t.ctx.Repo, "oast_mint"); !ok {
		return res, nil
	}
	if cur := t.count.Load(); cur >= oastMintPerRunCap {
		return tool.Result{
			Content: fmt.Sprintf("oast_mint rate-limited: %d canaries minted this run (cap=%d). "+
				"Poll the ones you have with oast_poll before minting more.", cur, oastMintPerRunCap),
			IsError: true,
		}, nil
	}

	t.once.Do(t.bringUp)
	if t.unavailable != "" {
		return tool.Result{Content: "oast_mint: " + t.unavailable, IsError: true}, nil
	}

	targetURL := argsString(args, "target_url")
	param := argsString(args, "param")
	kind := argsString(args, "kind")
	if kind == "" {
		kind = "olium-manual"
	}

	url := t.svc.GenerateURL(targetURL, param, kind, "olium-autopilot", "")
	if url == "" {
		return tool.Result{
			Content: "oast_mint: OAST service returned an empty URL (interactsh server may be unreachable). " +
				"Confirm blind classes another way or retry shortly.",
			IsError: true,
		}, nil
	}
	t.count.Add(1)

	nonce := url
	if i := strings.IndexByte(url, '.'); i > 0 {
		nonce = url[:i]
	}

	out := struct {
		URL   string `json:"url"`
		Nonce string `json:"nonce"`
		Hint  string `json:"hint"`
	}{
		URL:   url,
		Nonce: nonce,
		Hint: "Embed `url` in your payload (full URL for HTTP/SSRF; the host portion for DNS/XXE). " +
			"After firing, call oast_poll with search=\"" + nonce + "\" (give DNS 1-3s). " +
			"No callback after a couple polls = the target did not reach out — treat as not confirmed.",
	}
	body, _ := json.Marshal(out)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{"oast_url": url, "nonce": nonce},
	}, nil
}

// bringUp lazily constructs and starts the interactsh-backed Service from the
// run's resolved config. Runs exactly once; failure is cached in t.unavailable
// so every subsequent call returns the same clear message rather than retrying
// a broken client.
func (t *OASTMintTool) bringUp() {
	settings, err := config.LoadSettings(t.ctx.ConfigPath)
	if err != nil || settings == nil {
		t.unavailable = fmt.Sprintf("could not load config to initialise OAST: %v", err)
		return
	}
	if !settings.OAST.Enabled {
		t.unavailable = "OAST is disabled in config (agent.oast / oast.enabled). " +
			"Enable it to use blind out-of-band confirmation."
		return
	}
	svc, err := oast.New(&settings.OAST, nil, t.ctx.Repo, t.ctx.AgenticScanUUID, t.ctx.ProjectUUID, nil)
	if err != nil || svc == nil {
		t.unavailable = "OAST unavailable: interactsh client could not be created " +
			"(server unreachable or misconfigured). Blind callbacks can't be confirmed this run."
		return
	}
	svc.Start()
	t.svc = svc
}

// Shutdown flushes the grace period and closes the interactsh client. Safe to
// call unconditionally — a no-op when no canary was ever minted. autopilot.Run
// defers this so callbacks in flight when the agent halts still get persisted.
func (t *OASTMintTool) Shutdown() {
	t.shutdownOnce.Do(func() {
		if t.svc == nil {
			return
		}
		t.svc.Flush()
		t.svc.Close()
	})
}
