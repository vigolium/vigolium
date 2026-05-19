package tool

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas"
)

type browserProbeTool struct {
	// Overridable so tests don't spawn real browsers.
	probe func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error)

	// Wired by autopilot/swarm when a database is available; both empty
	// disables the capture=true affordance.
	captureSink    spitolas.CaptureSink
	captureProject string

	// schemaOnce builds the JSON schema lazily on first Schema() call and
	// reuses the result for the lifetime of the tool. The engine asks for
	// the schema repeatedly when listing tools to the provider, so the map
	// literal is otherwise rebuilt on every turn.
	schemaOnce   sync.Once
	cachedSchema map[string]any
}

// NewBrowserProbe returns a probe tool without network-capture support.
// Used by callers that don't have a database.Repository wired (TUI chat,
// tests, ad-hoc one-shots).
func NewBrowserProbe() Tool {
	return &browserProbeTool{probe: spitolas.ProbeURL}
}

// NewBrowserProbeWithCapture wires a CaptureSink so the agent can opt
// into network capture by passing `capture=true`. Records are persisted
// under source="browser-probe". Pass nil sink / empty projectUUID to
// fall back to the no-capture variant.
func NewBrowserProbeWithCapture(sink spitolas.CaptureSink, projectUUID string) Tool {
	if sink == nil || projectUUID == "" {
		return NewBrowserProbe()
	}
	return &browserProbeTool{
		probe:          spitolas.ProbeURL,
		captureSink:    sink,
		captureProject: projectUUID,
	}
}

func (*browserProbeTool) Name() string     { return "browser_probe" }
func (*browserProbeTool) Label() string    { return "Probe URL for JS dialogs" }
func (*browserProbeTool) Category() string { return CategoryBuiltin }

// Loads attacker-controlled JS in a real browser — never run in parallel with
// mutating tools speculatively.
func (*browserProbeTool) IsReadOnly() bool { return false }
func (*browserProbeTool) Description() string {
	return "Open a URL in a real headless browser and observe JavaScript dialogs (alert/confirm/prompt). " +
		"Returns whether a dialog fired and its message. Use this to confirm reflected or DOM-based XSS — " +
		"if alert(\"my-canary\") executes, the dialog is captured here even though no string reflection " +
		"may appear in the HTML response."
}

func (b *browserProbeTool) Schema() map[string]any {
	b.schemaOnce.Do(func() {
		props := map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "Fully-qualified http(s) URL to navigate to. Include any payload as part of the URL (query string or fragment).",
			},
			"wait_ms": map[string]any{
				"type":        "integer",
				"description": "Extra ms to wait after page stabilises so deferred (setTimeout-wrapped) alerts can fire. Default 700.",
				"default":     700,
			},
			"wait_selector": map[string]any{
				"type":        "string",
				"description": "Optional CSS selector to wait for before sampling dialogs.",
			},
			"nav_timeout_ms": map[string]any{
				"type":        "integer",
				"description": "Hard navigation timeout in ms. Default 25000.",
				"default":     25000,
			},
		}
		if b.captureSink != nil && b.captureProject != "" {
			props["capture"] = map[string]any{
				"type": "boolean",
				"description": "When true, every XHR/fetch/document request the browser issues during the " +
					"probe is recorded as an http_record under source=\"browser-probe\". Use this when probing " +
					"SPAs or pages whose JavaScript fans out into endpoints the HTTP-only spider can't see. " +
					"Default false (dialog-only XSS-confirm mode).",
				"default": false,
			}
		}
		b.cachedSchema = map[string]any{
			"type":       "object",
			"properties": props,
			"required":   []string{"url"},
		}
	})
	return b.cachedSchema
}

func (b *browserProbeTool) Execute(ctx context.Context, args map[string]any, _ UpdateFn) (Result, error) {
	url, _ := args["url"].(string)
	if url == "" {
		return Result{Content: "error: url is required", IsError: true}, nil
	}

	waitMS := 700
	if v, ok := args["wait_ms"].(float64); ok && int(v) >= 0 {
		waitMS = int(v)
	}
	navTimeoutMS := 25000
	if v, ok := args["nav_timeout_ms"].(float64); ok && int(v) > 0 {
		navTimeoutMS = int(v)
	}
	waitSel, _ := args["wait_selector"].(string)

	cfg := spitolas.ProbeConfig{
		URL:          url,
		WaitSelector: waitSel,
		WaitExtra:    time.Duration(waitMS) * time.Millisecond,
		NavTimeout:   time.Duration(navTimeoutMS) * time.Millisecond,
	}

	// Opt-in network capture. Only effective when the tool was constructed
	// with a sink — otherwise the arg is silently ignored (the schema for
	// the no-capture variant doesn't advertise it).
	if capture, _ := args["capture"].(bool); capture && b.captureSink != nil && b.captureProject != "" {
		cfg.CaptureSink = b.captureSink
		cfg.CaptureProjectUUID = b.captureProject
		cfg.CaptureSource = spitolas.CaptureSourceBrowserProbe
	}

	res, err := b.probe(ctx, cfg)
	if err != nil && (res == nil || len(res.Dialogs) == 0) {
		return Result{Content: fmt.Sprintf("probe failed: %v", err), IsError: true}, nil
	}
	if res == nil {
		return Result{Content: "probe returned no result", IsError: true}, nil
	}

	return Result{
		Content: renderProbeResult(url, res, err),
		Details: map[string]any{
			"dialog_fired": len(res.Dialogs) > 0,
			"dialogs":      dialogsToDetails(res.Dialogs),
			"final_url":    res.FinalURL,
			"title":        res.Title,
		},
	}, nil
}

func renderProbeResult(reqURL string, res *spitolas.ProbeResult, navErr error) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Requested:  %s\n", reqURL)
	if res.FinalURL != "" && res.FinalURL != reqURL {
		fmt.Fprintf(&out, "Final URL:  %s\n", res.FinalURL)
	}
	if res.Title != "" {
		fmt.Fprintf(&out, "Title:      %s\n", res.Title)
	}
	if navErr != nil {
		fmt.Fprintf(&out, "Nav note:   %v\n", navErr)
	}
	if len(res.Dialogs) == 0 {
		out.WriteString("\nNo JavaScript dialogs fired during navigation.\n")
		return out.String()
	}
	fmt.Fprintf(&out, "\nDialogs (%d):\n", len(res.Dialogs))
	for i, d := range res.Dialogs {
		fmt.Fprintf(&out, "  %d. %s: %q (frame: %s)\n", i+1, d.Type, d.Message, d.URL)
	}
	return out.String()
}

func dialogsToDetails(in []spitolas.DialogEvent) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, d := range in {
		out = append(out, map[string]any{
			"type":    d.Type,
			"message": d.Message,
			"url":     d.URL,
			"at":      d.At,
		})
	}
	return out
}
