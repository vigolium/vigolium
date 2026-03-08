package code_exec

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
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
var genericUnixPayloads = []string{
	"; sleep 5",
	"| sleep 5",
	"$(sleep 5)",
	"`sleep 5`",
	"() { :;}; /bin/sleep 5", // Shellshock
	"& sleep 5 &",
	"|| sleep 5",
	"&& sleep 5",
	`'";sleep 5;#`,
	`%0asleep 5%0a`,
}

// windowsPayloads are command injection payloads for Windows systems.
var windowsPayloads = []string{
	"& ping -n 6 127.0.0.1",
	"| ping -n 6 127.0.0.1",
	"& timeout /T 5 /NOBREAK",
}

// langPayloads maps language to specific command injection payloads.
var langPayloads = map[string][]string{
	"perl":   {"/bin/sleep 5|"},
	"php":    {`"; sleep(5);"`},
	"ruby":   {"#{`sleep 5`}"},
	"java":   {"${T(java.lang.Thread).sleep(5000)}"},
	"python": {"__import__('time').sleep(5)"},
}

// delaySeconds is the target delay in seconds for time-based detection.
const delaySeconds = 5

// confirmations is the number of retries to confirm vulnerability.
const confirmations = 3

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

	// Create all insertion points
	points, err := httpmsg.CreateAllInsertionPoints(ctx.Request().Raw(), true)
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

			// Initial check
			isVuln, sendErr := sendTimedRequest(fuzzedReq, httpClient)
			if sendErr != nil || !isVuln {
				continue
			}

			// Confirm with additional requests
			allConfirmed := true
			for range confirmations {
				isVuln, sendErr = sendTimedRequest(fuzzedReq, httpClient)
				if sendErr != nil || !isVuln {
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
