package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// kit groups small, stateless utility primitives that reuse the scanner's own
// building blocks but touch no database, project scope, or scan pipeline. They
// exist to be shelled out to by a coding agent / orchestrator: each reads
// files/stdin, honours -j/--json for machine consumption, and gates via exit
// codes. See `vigolium kit <cmd> --help`.
var kitCmd = &cobra.Command{
	Use:   "kit",
	Short: kitShortBase, // completed from the registered subcommands by deriveKitShort
	Long: `kit is a toolbox of small, composable primitives carved out of vigolium's own
engine — no database, no scan pipeline, no project scope. Each is a stateless
transform or probe meant to be driven by an orchestrator or run by hand.

  vigolium kit secret-scan <files|dirs|->   scan bytes for leaked credentials
  vigolium kit js-beautify  <file|url|->     unminify + unpack a JS bundle
  vigolium kit oast new|poll                 mint OOB callback URLs and drain hits
  vigolium kit harvest <domain...>           collect known URLs from public archives
  vigolium kit param-mine -t <url>           discover hidden parameters an endpoint accepts
  vigolium kit jwt-crack <token>             recover a JWT's HMAC secret from a wordlist
  vigolium kit wordlist [name]               list or print the built-in wordlists
  vigolium kit payload --class <c>           emit built-in payloads by class
  vigolium kit tmp-clean                     remove vigolium scratch left in the temp dir

All commands honour -j/--json for machine-readable output and read '-' as stdin.`,
}

func init() {
	rootCmd.AddCommand(kitCmd)
}

const kitShortBase = "Standalone security utilities"

// deriveKitShort lists every visible kit subcommand in kit's one-line summary.
// A hand-written list fell behind (it named four of eight tools), and the
// summary is what `vigolium --help` shows. Called from prepareCommandTree,
// because the subcommands register from init() in files that run after this
// one. Idempotent.
func deriveKitShort() {
	var names []string
	for _, sub := range kitCmd.Commands() {
		if sub.IsAvailableCommand() {
			names = append(names, sub.Name())
		}
	}
	if len(names) == 0 {
		kitCmd.Short = kitShortBase
		return
	}
	kitCmd.Short = kitShortBase + " (" + strings.Join(names, ", ") + ")"
}

// kitReadInput reads the bytes for a single positional argument: "-" or "" means
// stdin, otherwise the argument is a file path. The returned label is a
// human-readable source name ("stdin" or the path) used in output.
func kitReadInput(arg string) (data []byte, label string, err error) {
	if arg == "" || arg == "-" {
		b, rerr := readStdin()
		if rerr != nil {
			return nil, "stdin", fmt.Errorf("reading stdin: %w", rerr)
		}
		return b, "stdin", nil
	}
	b, rerr := os.ReadFile(arg)
	if rerr != nil {
		return nil, arg, rerr
	}
	return b, arg, nil
}

// kitLineScanner returns a bufio.Scanner over r sized for the long individual
// lines the kit commands read (wordlist entries, host lists) — the 1 MiB token
// cap that would otherwise be copy-pasted at each call site.
func kitLineScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return sc
}
