package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
)

// scan-request flags
var (
	scanReqInput  string
	scanReqTarget string
)

var scanRequestCmd = &cobra.Command{
	Use:   "scan-request",
	Short: "Scan a raw HTTP request for vulnerabilities",
	Long: `Read a raw HTTP request from file or stdin and run scanner modules against it.
Designed for pipeline integration and AI agent workflows.
Accepts raw HTTP requests, curl commands, and supports format auto-detection.`,
	Args: cobra.NoArgs,
	RunE: runScanRequestCmd,
}

func init() {
	rootCmd.AddCommand(scanRequestCmd)
	flags := scanRequestCmd.Flags()

	flags.StringVarP(&scanReqInput, "input", "i", "-", "Input file or - for stdin")
	flags.StringVarP(&scanReqTarget, "target", "t", "", "Override target URL (scheme://host)")
	flags.BoolVar(&scanURLNoPassive, "no-passive", false, "Skip passive modules")
	registerScanModuleFlags(flags)
	registerHTTPClientFlags(flags)
	registerPhaseFlags(flags)
	registerLightweightScanIOFlags(flags)
}

func runScanRequestCmd(_ *cobra.Command, _ []string) error {
	defer syncLogger()

	if err := resetFailOnGate(); err != nil {
		return err
	}

	// Read raw HTTP request
	var raw []byte
	var err error

	if scanReqInput == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(scanReqInput)
	}
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	rawStr := strings.TrimSpace(string(raw))
	if rawStr == "" {
		return fmt.Errorf("empty request input")
	}

	// Detect format and parse request
	var rr *httpmsg.HttpRequestResponse
	detected := detect.DetectStdinFormat(rawStr)
	if detected == detect.FormatCurl {
		// Curl command detected — parse via curl parser
		items, parseErr := detect.ParseStdinContent(rawStr, detect.FormatCurl)
		if parseErr != nil {
			return fmt.Errorf("failed to parse curl command: %w", parseErr)
		}
		rr = items[0]
	} else {
		// Raw HTTP (or fallback) — use existing raw HTTP parser
		if scanReqTarget != "" {
			rr, err = httpmsg.ParseRawRequestWithURL(rawStr, scanReqTarget)
		} else {
			rr, err = httpmsg.ParseRawRequest(rawStr)
		}
		if err != nil {
			return fmt.Errorf("failed to parse raw request: %w", err)
		}
	}

	// Extract method and target for output
	method := rr.Request().Method()
	target := rr.Target()

	// Route through the Runner when output/persistence/phase flags are in play;
	// otherwise take the fast in-memory direct path.
	return withFailOnGate(dispatchSingleScan(rr, target, method))
}
