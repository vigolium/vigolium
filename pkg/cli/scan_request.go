package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/spf13/cobra"
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
	Example: `  # Read a raw HTTP request from a file
  vigolium scan-request -i request.txt

  # Pipe a raw HTTP request from stdin
  printf 'POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=secret' | vigolium scan-request

  # Pipe a curl command from stdin (auto-detected)
  echo "curl -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\"}' https://example.com/api/login" | vigolium scan-request

  # Override the target host (useful for raw requests without full URL)
  vigolium scan-request -i request.txt --target https://staging.example.com

  # Scan with specific modules only
  printf 'GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n' | vigolium scan-request -m sqli -m xss

  # Skip passive modules
  vigolium scan-request -i request.txt --no-passive

  # Read from a Burp Suite saved request file
  vigolium scan-request -i burp-request.txt --target https://example.com

  # JSON output for scripting
  cat request.txt | vigolium scan-request --json`,
	Args: cobra.NoArgs,
	RunE: runScanRequestCmd,
}

func init() {
	rootCmd.AddCommand(scanRequestCmd)
	flags := scanRequestCmd.Flags()

	flags.StringVarP(&scanReqInput, "input", "i", "-", "Input file or - for stdin")
	flags.StringVar(&scanReqTarget, "target", "", "Override target URL (scheme://host)")
	flags.BoolVar(&scanURLNoPassive, "no-passive", false, "Skip passive modules")
	flags.BoolVar(&scanURLNoIP, "no-insertion-points", false, "Skip insertion point testing")

	registerPhaseFlags(flags)
}

func runScanRequestCmd(_ *cobra.Command, _ []string) error {
	defer syncLogger()

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

	// Delegate to Runner when any phase flag is set
	if hasPhaseFlags() {
		return runPhaseMode(rr, target, method)
	}

	return runScanWithRR(rr, target, method)
}
