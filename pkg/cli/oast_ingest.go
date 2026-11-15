package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var oastIngestProtocol string

var oastCmd = &cobra.Command{
	Use:   "oast",
	Short: "Attribute out-of-band callbacks logged by your own OAST endpoint",
	Long: `Work with out-of-band callbacks that a scan could not see live.

A scan run with a {nonce} template as oast_url (--oast-url
'https://{nonce}.cb.example.com' or 'https://cb.example.com/{nonce}') plants a
fresh nonce per probe and records which module, target and parameter planted
it. 'oast ingest' reads the callbacks your endpoint logged and turns the ones
carrying a recorded nonce into findings of the scan that planted them.

To mint callback URLs by hand, see 'vigolium kit oast'.`,
}

var oastIngestCmd = &cobra.Command{
	Use:   "ingest [file|-]",
	Short: "Turn logged OAST callbacks into findings of the scan that planted them",
	Long: `Read callbacks logged by your own OAST endpoint and attribute them to the
probes that planted them.

The scan must have run with a {nonce} oast_url: each probe then gets its own
nonce, and the nonce's context (scan, module, target, parameter, payload) is
stored in the project database. ingest looks for those nonces in each
callback's host or path (case-insensitively, since resolvers randomise DNS
name case), restores the context, rates the callback exactly like a live
interactsh callback, and saves the finding to the original scan. Callbacks
with no recorded nonce are ignored and counted as unmatched.

Formats (--format, required; on this command it names the input format):
  interactsh-json    interactsh-client -json output (one object per line, or an array)
  collaborator-json  Burp Collaborator polling output ({"responses":[...]}, an array, or one per line)
  raw-log            any line log (access log, DNS query log); each line is one callback.
                     The protocol is guessed per line (an HTTP request line → http,
                     SMTP verbs → smtp, else dns) unless --protocol is given.

Re-ingesting the same callbacks adds nothing: a callback already stored for
the nonce (same protocol, raw request and remote address) is skipped. The
nonce lookup is scoped to the current project; with -S --db <file> it searches
the whole file.`,
	Example: `  vigolium oast ingest callbacks.jsonl --format interactsh-json
  vigolium oast ingest burp-collab.json --format collaborator-json -j
  tail -n 5000 /var/log/nginx/cb.access.log | vigolium oast ingest - --format raw-log --protocol http`,
	Args: cobra.MaximumNArgs(1),
	RunE: runOASTIngest,
}

func init() {
	f := oastIngestCmd.Flags()
	f.StringVar(&oastIngestProtocol, "protocol", "", "Protocol of every raw-log line (http, https, dns, smtp); default: guessed per line")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Write to the standalone .sqlite named by --db with project scoping off")
	f.StringVar(&globalGlobDB, "glob-db", "", "Not supported: a --glob-db merge is a temporary copy, so ingested findings would be lost")
	_ = f.MarkHidden("glob-db")

	oastCmd.AddCommand(oastIngestCmd)
	rootCmd.AddCommand(oastCmd)
}

// oastIngestProtocols are the --protocol values a raw-log line can take.
var oastIngestProtocols = []string{"http", "https", "dns", "smtp", "ldap", "ftp"}

func runOASTIngest(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	// --format is the global flag; here it names the input format, and the
	// global default ("console") does not apply.
	format := ""
	if f := cmd.Flag("format"); f != nil && f.Changed {
		format = strings.ToLower(strings.TrimSpace(globalFormat))
	}
	if format == "" {
		return usageErrorf("oast ingest needs --format (%s)", strings.Join(oast.IngestFormats(), ", "))
	}
	if !slices.Contains(oast.IngestFormats(), format) {
		return usageErrorf("invalid --format %q (want one of: %s)", globalFormat, strings.Join(oast.IngestFormats(), ", "))
	}
	protocol := strings.ToLower(strings.TrimSpace(oastIngestProtocol))
	if protocol != "" {
		if format != oast.FormatRawLog {
			return usageErrorf("--protocol only applies to --format raw-log: the JSON formats carry each callback's protocol")
		}
		if !slices.Contains(oastIngestProtocols, protocol) {
			return usageErrorf("invalid --protocol %q (want one of: %s)", oastIngestProtocol, strings.Join(oastIngestProtocols, ", "))
		}
	}
	if strings.TrimSpace(globalGlobDB) != "" {
		return usageErrorf("oast ingest cannot write through --glob-db: the merge is a temporary copy that is discarded on exit. Ingest into one source with -S --db <file.sqlite>")
	}
	if path := strings.TrimSpace(globalDB); path != "" && isJSONLSource(path) {
		return usageErrorf("oast ingest cannot write to a .jsonl export (%s): it is loaded into a temporary database that is discarded on exit", path)
	}

	src := "-"
	if len(args) == 1 {
		src = args[0]
	}
	var in io.Reader
	if src == "-" {
		if len(args) == 0 && stdinIsTerminal() {
			return usageErrorf("oast ingest needs a file argument, or callbacks piped on stdin")
		}
		in = os.Stdin
	} else {
		fh, err := os.Open(src)
		if err != nil {
			return usageErrorf("cannot open %s: %v", src, err)
		}
		defer func() { _ = fh.Close() }()
		in = fh
	}

	callbacks, err := oast.ParseCallbacks(in, format, oast.ParseOptions{Protocol: protocol})
	if err != nil {
		return usageErrorf("parsing %s as %s: %v", src, format, err)
	}

	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	var db *database.DB
	if statelessReadRequested() {
		db, err = openStatelessDB(globDBSkipSet{})
	} else {
		db, err = getDB()
	}
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	res, err := oast.Ingest(context.Background(), database.NewRepository(db), projectUUID, callbacks)
	if err != nil {
		return err
	}

	if globalJSON {
		return emitMutation(cmd, "", mutationResult{
			Changed: len(res.Findings) > 0 || res.Matched > res.Duplicates,
			Action:  "import",
			Items:   res.Findings,
			Extra: map[string]any{
				"format":     format,
				"callbacks":  res.Callbacks,
				"matched":    res.Matched,
				"unmatched":  res.Unmatched,
				"duplicates": res.Duplicates,
			},
		}, withProjectScope(projectUUID), withDBPath(resolvedReadDBPath()))
	}
	printOASTIngestResult(res)
	return nil
}

func printOASTIngestResult(res *oast.IngestResult) {
	for _, f := range res.Findings {
		target := f.TargetURL
		if f.Param != "" {
			target += " [" + f.Param + "]"
		}
		fmt.Printf("%s %s %s %s via %s (scan %s)\n", terminal.SuccessSymbol(), terminal.BoldYellow(f.Severity),
			f.ModuleID, target, f.Protocol, f.ScanUUID)
	}
	fmt.Printf("%s %d callback(s): %d matched a recorded nonce, %d unmatched (ignored), %d already ingested; %d finding(s) saved\n",
		terminal.InfoSymbol(), res.Callbacks, res.Matched, res.Unmatched, res.Duplicates, len(res.Findings))
}
