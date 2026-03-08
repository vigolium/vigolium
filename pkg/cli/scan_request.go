package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
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
	Long:  "Read a raw HTTP request from file or stdin and run scanner modules against it.\nDesigned for pipeline integration and AI agent workflows.",
	Args:  cobra.NoArgs,
	RunE:  runScanRequestCmd,
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

	// Parse request
	var rr *httpmsg.HttpRequestResponse
	if scanReqTarget != "" {
		rr, err = httpmsg.ParseRawRequestWithURL(rawStr, scanReqTarget)
	} else {
		rr, err = httpmsg.ParseRawRequest(rawStr)
	}
	if err != nil {
		return fmt.Errorf("failed to parse raw request: %w", err)
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
