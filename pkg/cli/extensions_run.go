package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/jsext/exttest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium ext run` (and `ext eval --record-uuid`, the same thing): run one
// extension's handlers against one stored record, offline by default, and
// report what it found. The inner loop of writing an extension: edit, run
// against the record that should fire, read the result, repeat — no scan.

var (
	extRunRecordUUID   string
	extRunHandler      string
	extRunInsertion    string
	extRunAllowNetwork bool
)

var extensionsRunCmd = &cobra.Command{
	Use:   "run [file]",
	Short: "Run one extension against a stored record (offline unless --allow-network)",
	Long: `Load one extension (.js, .ts or .vgm.yaml) the way a scan does and call its
handlers against a stored HTTP record. Same as "ext eval --record-uuid".

The extension is named with --ext (or as the argument). The record comes from
the database read-only: vigolium.db reads work, record.annotate / addRemarks
and vigolium.ingest return false. Every request the extension makes fails with
"network disabled in ext eval; pass --allow-network" (vigolium.http.* throws)
and is counted in network_calls_blocked; --allow-network sends them for real.
vigolium.oast and vigolium.agent are not available.

With no --handler, every handler the module's scanTypes declare runs.
scanPerInsertionPoint runs once per insertion point the module accepts, or
only on --insertion TYPE:name (URL_PARAM:id, BODY_PARAM:user, HEADER:X-Api-Key).

Exit 1 when a handler threw (the errors list says where); exit 2 for a bad
command line, an unknown record, or an extension that does not load.`,
	Example: `  vigolium ext run --ext check.js --record-uuid 3f2a9c1e
  vigolium ext run --ext check.js --record-uuid 3f2a9c1e --handler scanPerInsertionPoint --insertion URL_PARAM:id
  vigolium ext eval --ext check.js --record-uuid 3f2a9c1e -j`,
	Args: cobra.MaximumNArgs(1),
}

func init() {
	// Assigned here: the run function names extensionsRunCmd (its document's
	// command), which a composite literal cannot refer back to.
	extensionsRunCmd.RunE = func(cmd *cobra.Command, args []string) error {
		path := ""
		if len(args) == 1 {
			path = args[0]
		}
		return runExtensionOnRecord(cmd, path)
	}
	extensionsCmd.AddCommand(extensionsRunCmd)
	for _, c := range []*cobra.Command{extensionsRunCmd, extensionsEvalCmd} {
		registerExtRunFlags(c)
	}

	registerCommandSchema(contract.Command{Name: "extensions run", Item: extRunResult{}, Extras: extRunExtras{},
		Description: "What one extension reported for one stored record (ext run, ext eval --record-uuid): items are its results; errors are the handler calls that threw; network_calls_blocked counts the requests an offline run refused. ok is false when a handler threw (exit 1)."})
}

func registerExtRunFlags(c *cobra.Command) {
	f := c.Flags()
	f.StringVarP(&extRunRecordUUID, "record-uuid", "u", "", "Stored HTTP record to run the extension against (UUID or unique prefix; see vigolium traffic)")
	f.StringVar(&extRunHandler, "handler", "", "Handler to call: scanPerRequest, scanPerHost or scanPerInsertionPoint (default: every handler the module declares)")
	f.StringVar(&extRunInsertion, "insertion", "", "Insertion point for scanPerInsertionPoint as TYPE:name, e.g. URL_PARAM:id (default: every point)")
	f.BoolVar(&extRunAllowNetwork, "allow-network", false, "Let the extension send requests (default: every request fails and is counted)")
}

// extRunResult is one result the extension reported, with the module's
// defaults filled in the way a scan fills them.
type extRunResult struct {
	ModuleID    string   `json:"module_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	URL         string   `json:"url,omitempty"`
	Matched     string   `json:"matched,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Param       string   `json:"param,omitempty"`
	Payload     string   `json:"payload,omitempty"`
	Extracted   []string `json:"extracted,omitempty"`
	Request     string   `json:"request,omitempty"`
	Response    string   `json:"response,omitempty"`
}

// extRunExtras are the document's own top-level keys.
type extRunExtras struct {
	ModuleID   string `json:"module_id"`
	RecordUUID string `json:"record_uuid"`
	// Handler is the --handler asked for; "" ran every declared handler.
	Handler string `json:"handler"`
	// Handlers are the handlers that were called.
	Handlers            []string            `json:"handlers"`
	Calls               int                 `json:"calls"`
	Errors              []exttest.CallError `json:"errors"`
	NetworkAllowed      bool                `json:"network_allowed"`
	NetworkCallsBlocked int64               `json:"network_calls_blocked"`
	DurationMS          int64               `json:"duration_ms"`
}

// extRunFlagsSet reports whether any record-mode flag was given.
func extRunFlagsSet(cmd *cobra.Command) bool {
	for _, name := range []string{"record-uuid", "handler", "insertion", "allow-network"} {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			return true
		}
	}
	return false
}

// resolveExtRunPath picks the one extension to run: the argument or a single
// --ext.
func resolveExtRunPath(arg string) (string, error) {
	switch {
	case arg != "" && len(globalExtScripts) > 0:
		return "", usageErrorf("name the extension once: as the argument or with --ext, not both")
	case arg != "":
		return arg, nil
	case len(globalExtScripts) == 1:
		return globalExtScripts[0], nil
	case len(globalExtScripts) > 1:
		return "", usageErrorf("--ext names %d extensions; ext run takes exactly one", len(globalExtScripts))
	}
	return "", usageErrorf("name the extension to run: --ext check.js (or as the argument)")
}

func runExtensionOnRecord(cmd *cobra.Command, arg string) error {
	defer syncLogger()

	path, err := resolveExtRunPath(arg)
	if err != nil {
		return err
	}
	uuid := strings.TrimSpace(extRunRecordUUID)
	if uuid == "" {
		return usageErrorf("--record-uuid is required: name the stored record to run against.\n\n" +
			"Find one with: vigolium traffic --compact --fields uuid,url -j")
	}
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}

	// Read intent: the run must never write, and must not wait on a scan
	// writing the same store.
	db, err := getDBFor(clicommon.IntentRead)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer closeDatabaseOnExit()
	repo := database.NewRepository(db)

	rec, _, err := loadRecordRef(context.Background(), repo, uuid)
	if isRecordNotFound(err) {
		return clicommon.AsUsageError(err)
	}
	if err != nil {
		return err
	}
	rr, err := database.RecordToHttpRequestResponse(rec)
	if err != nil {
		return fmt.Errorf("record %s has no usable request: %w", rec.UUID, err)
	}

	var requester *http.Requester
	if extRunAllowNetwork {
		r, cleanup, err := setupJsHTTPStack(settings)
		if err != nil {
			return err
		}
		defer cleanup()
		requester = r
	} else {
		requester = exttest.NewOfflineRequester()
	}

	base := settings.DynamicAssessment.Extensions
	ext, err := exttest.Load(path, exttest.Options{
		HTTPClient:  requester,
		Repository:  repo,
		ProjectUUID: rec.ProjectUUID,
		Base:        &base,
	})
	if err != nil {
		var le *exttest.LoadError
		if errors.As(err, &le) {
			return clicommon.AsUsageError(clicommon.NewCodedError(apicontract.CodeExtensionLoadFailed, err))
		}
		return usageErrorf("%v", err)
	}

	outcome, err := ext.Run(rr, exttest.RunOptions{
		Handler:    extRunHandler,
		Insertion:  extRunInsertion,
		RecordUUID: rec.UUID,
	})
	if err != nil {
		return usageErrorf("%v", err)
	}

	extras := extRunExtras{
		ModuleID:            outcome.ModuleID,
		RecordUUID:          rec.UUID,
		Handler:             extRunHandler,
		Handlers:            outcome.Handlers,
		Calls:               outcome.Calls,
		Errors:              outcome.Errors,
		NetworkAllowed:      extRunAllowNetwork,
		NetworkCallsBlocked: requester.RequestsRefused(),
		DurationMS:          outcome.Duration.Milliseconds(),
	}
	if extras.Errors == nil {
		extras.Errors = []exttest.CallError{}
	}
	items := make([]extRunResult, 0, len(outcome.Results))
	for _, r := range outcome.Results {
		items = append(items, toExtRunResult(r))
	}

	var runErr error
	if n := len(outcome.Errors); n > 0 {
		runErr = codedErrorf(apicontract.CodeFailed, "%s threw in %d of %d handler call(s): %s",
			outcome.ModuleID, n, outcome.Calls, outcome.Errors[0].Message)
	}

	if globalJSON {
		// Documented as one shape whichever spelling ran it.
		opts := []envOpt{
			withExtra("module_id", extras.ModuleID),
			withExtra("record_uuid", extras.RecordUUID),
			withExtra("handler", extras.Handler),
			withExtra("handlers", extras.Handlers),
			withExtra("calls", extras.Calls),
			withExtra("errors", extras.Errors),
			withExtra("network_allowed", extras.NetworkAllowed),
			withExtra("network_calls_blocked", extras.NetworkCallsBlocked),
			withExtra("duration_ms", extras.DurationMS),
		}
		if err := emitRead(extensionsRunCmd, "results", items, int64(len(items)), 0, len(items), opts...); err != nil {
			return err
		}
		return runErr
	}

	printExtRun(path, extras, items)
	return runErr
}

func toExtRunResult(r *output.ResultEvent) extRunResult {
	return extRunResult{
		ModuleID:    r.ModuleID,
		Name:        r.Info.Name,
		Severity:    r.Info.Severity.String(),
		Confidence:  r.Info.Confidence.String(),
		URL:         r.URL,
		Matched:     r.Matched,
		Description: r.Info.Description,
		Tags:        r.Info.Tags,
		Param:       r.FuzzingParameter,
		Payload:     r.Payload,
		Extracted:   r.ExtractedResults,
		Request:     r.Request,
		Response:    r.Response,
	}
}

func printExtRun(path string, x extRunExtras, items []extRunResult) {
	fmt.Printf("%s %s (%s) on record %s: %s, %d call(s), %dms\n",
		terminal.InfoSymbol(), x.ModuleID, path, x.RecordUUID,
		strings.Join(x.Handlers, ", "), x.Calls, x.DurationMS)
	if len(items) == 0 {
		fmt.Printf("%s no findings\n", terminal.Gray("-"))
	}
	for _, it := range items {
		fmt.Printf("\n%s %s %s\n", terminal.SuccessSymbol(), it.Name, terminal.Gray("["+it.Severity+"/"+it.Confidence+"]"))
		if it.URL != "" {
			fmt.Printf("  url:     %s\n", it.URL)
		}
		if it.Matched != "" && it.Matched != it.URL {
			fmt.Printf("  matched: %s\n", it.Matched)
		}
		if it.Param != "" {
			fmt.Printf("  param:   %s\n", it.Param)
		}
		if it.Description != "" {
			for _, line := range strings.Split(strings.TrimSpace(it.Description), "\n") {
				fmt.Printf("  %s\n", line)
			}
		}
	}
	for _, e := range x.Errors {
		where := e.Handler
		if e.Insertion != "" {
			where += " @ " + e.Insertion
		}
		fmt.Printf("\n%s %s: %s\n", terminal.ErrorSymbol(), where, e.Message)
	}
	if x.NetworkCallsBlocked > 0 {
		fmt.Printf("\n%s %d network call(s) blocked; pass --allow-network to send them\n",
			terminal.WarningSymbol(), x.NetworkCallsBlocked)
	}
}
