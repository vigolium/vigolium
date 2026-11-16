package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/browsercookie"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/utils"
)

var (
	kitCookiesScope        string
	kitCookiesApex         bool
	kitCookiesBrowsers     []string
	kitCookiesProfiles     []string
	kitCookiesUserDataDirs []string
	kitCookiesNames        []string
	kitCookiesFormat       string
	kitCookiesOutput       string
	kitCookiesStdout       bool
	kitCookiesReveal       bool
	kitCookiesIncludeExp   bool
	kitCookiesSameSite     string
	kitCookiesRequireMatch bool
	kitCookiesWithStorage  bool
	kitCookiesCloneDir     string
	kitCookiesAck          bool
	kitCookiesNoPrompt     bool

	// `profiles` and `doctor` keep their own selector flags rather than
	// sharing the read command's: cobra binds a flag to a pointer, and three
	// commands pointing at one variable makes each one's default depend on
	// which was registered last.
	kitCookiesProfilesBrowsers     []string
	kitCookiesProfilesUserDataDirs []string
	kitCookiesDoctorBrowsers       []string
	kitCookiesDoctorUserDataDirs   []string
	kitCookiesSkipKeyringProbe     bool
)

var kitCookiesCmd = &cobra.Command{
	Use:   "cookies [domain...]",
	Short: "Read cookies for a domain out of this machine's own browser profiles",
	Long: `Read the cookies your local browser already holds for a domain, and hand them to
something that can use them — Playwright, curl, or vigolium's own authenticated
scan phases — instead of copying values out of devtools by hand.

  vigolium kit cookies app.acme.test                         # redacted listing
  vigolium kit cookies app.acme.test -j                      # JSON (values masked under a coding agent)
  vigolium kit cookies acme.test --apex --as playwright -o state.json
  vigolium kit cookies app.acme.test --with-storage --as playwright -o state.json
  vigolium kit cookies app.acme.test --clone-profile ./agent-profile   # carries IndexedDB
  vigolium kit cookies acme.test --as header --stdout        # a Cookie: header (a shell, not an agent)
  vigolium kit cookies profiles                              # which profiles exist
  vigolium kit cookies doctor                                # will this work here?

Values are redacted by default. They are written only when you ask for them:
--as with -o (a file created mode 0600, because what lands in it is a live
credential), --as with --stdout, -j, or --reveal.

Under a coding agent (CLAUDECODE and the like, or VIGOLIUM_REDACT=1) a value
must not land in the transcript: -j masks every cookie and storage value, as
every -j view masks credentials, and --stdout is refused. Values then leave
only through --as ... -o <file>, which a session can be loaded from without
anyone reading it. --reveal, --no-redact or VIGOLIUM_REDACT=0 lift this for one
deliberate read.

An -o file that already exists is never replaced by an empty or failed read:
a read that found nothing exits 3 and leaves it; one that could not decrypt
(keyring_denied, ...) exits 1 and leaves it.

Scope decides which cookies count, and it is not a string compare:
  --scope host        cookies a request to that exact host would carry (default)
  --scope subdomains  also cookies belonging to hosts below it
  --scope apex        widen to the registrable domain first (--apex is a shorthand)

--clone-profile writes a scoped copy of the browser profile instead of an
export, and is the only output that carries IndexedDB — where Firebase Auth and
several SPA auth libraries keep the session a cookie export cannot reproduce.
Everything belonging to other sites is deleted from the copy. Open it with
Playwright's launchPersistentContext; the directory holds a README saying how.

--with-storage adds each matching origin's localStorage and sessionStorage.
localStorage lands in the storageState's origins[] (--as playwright) so a
Playwright context restores cookies and storage together. sessionStorage has no
field there, so --as playwright leaves it out: write it with --as
playwright-init and pass the script to context.addInitScript. json, jsonl and
-j carry both. sessionStorage is per-tab, so keys from several open tabs are
merged into one set. Storage is
isolated per ORIGIN, not per cookie domain, so https://app.acme.test and
https://acme.test are separate stores that share nothing — widen with
--scope subdomains to collect both.

Multiple browsers and profiles are read at once; --browser and --profile narrow
it, and --profile takes the name you see in the browser ("Work") as well as the
directory ("Profile 3"). A browser installed somewhere non-standard — Chrome for
Testing, Chrome Beta, a Playwright profile — is reached with --user-data-dir.

--no-prompt never raises an OS approval prompt: on macOS a store whose key is
in the login keychain fails keyring_denied without being opened. Use it for an
unattended read; without it a prompt nobody answers is abandoned after two
minutes, also as keyring_denied.

Exit codes: 0 read something (or nothing, cleanly), 1 a store could not be read
(the JSON error code says why: keyring_denied, browser_encryption_unsupported),
2 bad usage, 3 nothing matched and --require-match was given, or an existing -o
file was kept because nothing matched.`,
	// Declared rather than inherited: `cookies` carries subcommands AND takes
	// positional domains, and cobra's legacy handling accepts that positional
	// only as an accident of this command not being the root.
	Args: cobra.ArbitraryArgs,
	RunE: runKitCookies,
}

var kitCookiesProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "List the browser profiles on this machine and their cookie stores",
	Long: `List every browser profile whose cookie store this machine exposes, with the
label you see in the browser alongside the directory name on disk.

  vigolium kit cookies profiles
  vigolium kit cookies profiles -j
  vigolium kit cookies profiles --user-data-dir ~/chrome-for-testing

No cookie is read and no keyring secret is requested, so this never prompts.`,
	Args: cobra.NoArgs,
	RunE: runKitCookiesProfiles,
}

var kitCookiesDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check whether cookies can be read here, and say what is blocking it",
	Long: `Diagnose this machine's ability to read browser cookies: which stores exist,
whether their decryption keys are reachable, and whether anything about the
profiles makes them unreadable.

  vigolium kit cookies doctor
  vigolium kit cookies doctor -j
  vigolium kit cookies doctor --skip-keyring-probe  # do not raise the prompt

On macOS this is the right place to test keychain access: it asks for the key
deliberately. Choose "Allow", which permits this one read, not "Always Allow":
that adds /usr/bin/security to the key's access list, after which any process
on this machine can read the browser's key — and with it every cookie of every
site — without a prompt. Each later read asks again; the prompt is the guard.
The key itself is discarded — only whether the read was permitted is reported.

Run this first when a read comes back empty. Every way a cookie read can fail
otherwise looks exactly like "that domain has no cookies".

Exits 1 when something blocking was found.`,
	Args: cobra.NoArgs,
	RunE: runKitCookiesDoctor,
}

func init() {
	f := kitCookiesCmd.Flags()
	f.StringVar(&kitCookiesScope, "scope", "host", "Domain scope: host, subdomains, apex")
	f.BoolVar(&kitCookiesApex, "apex", false, "Shorthand for --scope apex: widen each domain to its registrable domain")
	f.StringSliceVar(&kitCookiesBrowsers, "browser", nil, "Only these browsers (comma-separated): "+strings.Join(browsercookie.SupportedBrowsers(), ", "))
	f.StringSliceVar(&kitCookiesProfiles, "profile", nil, "Only these profiles, by label (\"Work\") or directory (\"Profile 3\")")
	f.StringSliceVar(&kitCookiesUserDataDirs, "user-data-dir", nil, "Extra Chromium user-data directories to read (Chrome for Testing, Chrome Beta, a Playwright profile)")
	f.StringSliceVar(&kitCookiesNames, "name", nil, "Only cookies with these names")
	f.StringVar(&kitCookiesFormat, "as", "", "Write values in this format: "+browsercookie.FormatList())
	f.StringVarP(&kitCookiesOutput, "output", "o", "", "Write --as output to this file, mode 0600")
	f.BoolVar(&kitCookiesStdout, "stdout", false, "Write --as output to stdout instead of a file")
	f.BoolVar(&kitCookiesReveal, "reveal", false, "Show cookie and storage values: in the human listing, in -j under a coding agent, and allow --stdout under one")
	f.BoolVar(&kitCookiesIncludeExp, "include-expired", false, "Keep cookies whose expiry has already passed")
	f.StringVar(&kitCookiesSameSite, "same-site", "", "Force the SameSite attribute on export: strict, lax, none")
	f.StringVar(&kitCookiesCloneDir, "clone-profile", "", "Write a scoped browser-profile clone to this directory — the only export that carries IndexedDB (open it with Playwright's launchPersistentContext)")
	f.BoolVar(&kitCookiesWithStorage, "with-storage", false, "Also read each matching origin's localStorage and sessionStorage (Chromium profiles). Reported by -j, --as json/jsonl (both), --as playwright (localStorage only) and --as playwright-init (sessionStorage only)")
	f.BoolVar(&kitCookiesRequireMatch, "require-match", false, "Exit 3 when no cookie matched (for agent gating)")
	f.BoolVar(&kitCookiesAck, "yes", false, "Skip the first-run notice about approval prompts and endpoint-security alerts")
	f.BoolVar(&kitCookiesNoPrompt, "no-prompt", false, "Never raise an OS approval prompt: a store whose key needs one (the macOS login keychain) fails keyring_denied instead")

	pf := kitCookiesProfilesCmd.Flags()
	pf.StringSliceVar(&kitCookiesProfilesBrowsers, "browser", nil, "Only these browsers (comma-separated)")
	pf.StringSliceVar(&kitCookiesProfilesUserDataDirs, "user-data-dir", nil, "Extra Chromium user-data directories to inspect")

	df := kitCookiesDoctorCmd.Flags()
	df.StringSliceVar(&kitCookiesDoctorBrowsers, "browser", nil, "Only these browsers (comma-separated)")
	df.StringSliceVar(&kitCookiesDoctorUserDataDirs, "user-data-dir", nil, "Extra Chromium user-data directories to inspect")
	df.BoolVar(&kitCookiesSkipKeyringProbe, "skip-keyring-probe", false, "Do not ask the OS keyring for a key, so no approval prompt is raised (reports access as untested)")

	kitCookiesCmd.AddCommand(kitCookiesProfilesCmd, kitCookiesDoctorCmd)
	kitCmd.AddCommand(kitCookiesCmd)
}

// kitCookiesRead is the store read; a var so a test can hand the command a
// result (a denied keyring, an empty profile) without a real browser profile or
// the OS keychain.
var kitCookiesRead = browsercookie.Read

// kitCookiesReport is the -j payload for a read: the rows plus the extras the
// schema registry publishes.
//
// The extras are EMBEDDED rather than restated, so the registered schema and
// the emitted document are one declaration. Written out twice they had already
// drifted within a single change — the registry copy omitted `unreadable` and
// `clone`, both of which this command emits, so the published schema
// under-described its own output. Go flattens an embedded struct, so the wire
// form is unchanged.
type kitCookiesReport struct {
	kitCookiesExtras
	Cookies []browsercookie.Cookie `json:"cookies"`
}

func runKitCookies(cmd *cobra.Command, args []string) error {
	domains, err := kitCollectDomains(args)
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		// Refusing a bare invocation is deliberate. Reading every cookie in
		// every profile is both the least likely thing an operator wants and
		// the most sensitive thing this command can do; an explicit domain
		// keeps a mistyped command from dumping an entire browser session
		// store. Use --scope apex to widen on purpose.
		return usageErrorf("name at least one domain (a bare `kit cookies` would read every cookie in every profile; pass a domain, or --scope apex to widen)")
	}

	scope, err := kitCookiesResolveScope(cmd)
	if err != nil {
		return err
	}
	format, err := validateKitCookiesFlags()
	if err != nil {
		return err
	}

	wantsValues := globalJSON || kitCookiesReveal || format != ""
	if wantsValues {
		kitCookiesNotice(cmd)
	}

	// SIGTERM as well as an interrupt: a --clone-profile cut short must get to
	// remove its staging directory rather than die holding every site's state.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	query := browsercookie.Query{
		Domains:        domains,
		Scope:          scope,
		Names:          kitCookiesNames,
		Browsers:       kitCookiesBrowsers,
		Profiles:       kitCookiesProfiles,
		UserDataDirs:   kitCookiesUserDataDirs,
		WithStorage:    kitCookiesWithStorage,
		IncludeExpired: kitCookiesIncludeExp,
		NoPrompt:       kitCookiesNoPrompt,
	}
	res, err := kitCookiesRead(ctx, query)
	if err != nil {
		if usage := selectorAsUsage(err); usage != nil {
			return usage
		}
		return err
	}

	report := kitCookiesReport{
		kitCookiesExtras: kitCookiesExtras{
			Domains:      domains,
			Scope:        scope.String(),
			Matched:      res.Matcher.Targets(),
			Count:        len(res.Cookies),
			StorageItems: res.StorageItems(),
			Origins:      res.Origins,
			Unreadable:   res.Unreadable,
			Stores:       res.Stores,
			Warnings:     res.Warnings,
			Problem:      string(res.Problem()),
		},
		Cookies: res.Cookies,
	}

	// A read that found nothing because nothing could be decrypted is a
	// failure, not an empty session: no artifact is written from it, so a
	// denied keyring can never overwrite a good state.json or clone a profile
	// with its cookies missing. The coded error below says why.
	problem := res.Problem()
	failed := problem != browsercookie.ProblemNone && len(res.Cookies) == 0

	// The requested artifact is written before anything is reported, so a
	// failure to write it is not masked by a successful-looking listing.
	var keptOutput error
	if kitCookiesCloneDir != "" && !failed {
		if len(res.Cookies) == 0 && len(res.Origins) == 0 {
			return usageErrorf("nothing matched %s, so there is no session to clone", strings.Join(domains, ", "))
		}
		source, err := kitCookiesCloneSource(res)
		if err != nil {
			return err
		}
		clone, err := browsercookie.CloneProfile(ctx, source, res.Matcher, res.Cookies, kitCookiesCloneDir)
		if err != nil {
			if usage := selectorAsUsage(err); usage != nil {
				return usage
			}
			return codedErrorf(apicontract.CodeExportFailed, "cloning %s: %w", source.Describe(), err)
		}
		report.Clone = &clone
	}
	if format != "" && !failed {
		var buf bytes.Buffer
		if err := browsercookie.Render(&buf, res.Cookies, format, browsercookie.RenderOptions{
			SameSite: kitCookiesSameSite,
			Origins:  res.Origins,
		}); err != nil {
			return err
		}
		for _, w := range kitCookiesExportWarnings(res, format) {
			fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(), w)
		}
		switch {
		case kitCookiesOutput != "" && kitCookiesExportEmpty(res, format) && fileExists(kitCookiesOutput):
			// An empty export replacing a saved session is how a read in the
			// wrong profile, or before the login finished, destroys the one
			// that worked. Kept, and said so: exit 3, as nothing matched.
			report.OutputKept = kitCookiesOutput
			keptOutput = asMatchErrorf("nothing matched %s; kept the existing %s rather than replace it with an empty export",
				strings.Join(domains, ", "), kitCookiesOutput)
		case kitCookiesStdout:
			// writeBody is the repo's raw-bytes-to-stdout writer, shared with
			// `skills get`, `kit wordlist` and `schema` — the commands whose
			// artifact IS the output. Using it means this command needs no
			// machine-output lint exemption of its own.
			writeBody(buf.Bytes())
		default:
			if err := kitCookiesWriteSecret(kitCookiesOutput, buf.Bytes()); err != nil {
				return err
			}
			report.Output = kitCookiesOutput
		}
	}

	if globalJSON {
		// Under -j redaction the document is masked like every other -j view;
		// the values reach a file through --as -o, never the transcript.
		report = redactKitCookiesReport(jsonRedactOn && !kitCookiesReveal, report)
		if err := emitStructRead(cmd, report, "cookies"); err != nil {
			return err
		}
	} else {
		kitCookiesPrintHuman(report, format)
	}

	// A problem outranks an empty result: "nothing matched" and "nothing could
	// be read" are different answers and an agent branches on which it got.
	if failed {
		return codedErrorf(kitCookiesErrorCode(problem), "%s: %s", kitCookiesProblemSummary(problem), res.ProblemDetail())
	}
	if keptOutput != nil {
		return keptOutput
	}
	if kitCookiesRequireMatch && len(res.Cookies) == 0 {
		return asMatchErrorf("--require-match: no cookie matched %s", strings.Join(domains, ", "))
	}
	return nil
}

// validateKitCookiesFlags checks the flag combination before anything is
// read, and returns the --as format ("" for none). Every refusal is a usage
// error (exit 2). It sets --with-storage under --clone-profile: the clone is
// built from the same scope the read uses, and reading storage is how the
// summary can say what the clone carries.
func validateKitCookiesFlags() (browsercookie.Format, error) {
	if err := browsercookie.ValidateSameSite(kitCookiesSameSite); err != nil {
		return "", asUsageError(err)
	}
	var format browsercookie.Format
	if kitCookiesFormat != "" {
		var err error
		if format, err = browsercookie.ParseFormat(kitCookiesFormat); err != nil {
			return "", asUsageError(err)
		}
		if kitCookiesOutput == "" && !kitCookiesStdout {
			return "", usageErrorf("--as writes cookie values: pass -o <file> to write them to a 0600 file, or --stdout to accept them on stdout")
		}
	}
	if kitCookiesOutput != "" && kitCookiesFormat == "" {
		return "", usageErrorf("-o needs --as (%s)", browsercookie.FormatList())
	}
	if kitCookiesOutput != "" && kitCookiesStdout {
		return "", usageErrorf("--stdout and -o both name a destination: pick one")
	}
	// Both would own stdout, and the export is not the envelope: a driver
	// reading one document per invocation would get a cookie jar glued to it.
	if kitCookiesCloneDir != "" {
		if kitCookiesFormat != "" {
			return "", usageErrorf("--clone-profile writes a profile directory, not a %s document: use one or the other", kitCookiesFormat)
		}
		kitCookiesWithStorage = true
	}
	if kitCookiesStdout && globalJSON {
		return "", usageErrorf("--stdout and -j both write to stdout: use -o <file> with -j, or drop -j")
	}
	// --stdout is the raw form of the values -j would mask, so the -j
	// redaction rule (a coding agent, --redact, VIGOLIUM_REDACT) applies to it
	// as if -j were on (redactRequested, resolved once in the root pre-run).
	if kitCookiesStdout && !kitCookiesReveal && redactRequested {
		return "", usageErrorf("--stdout would print a live session into a coding agent's transcript: write it with -o <file> (mode 0600) and load the file, or pass --reveal to print it on purpose")
	}
	return format, nil
}

// selectorAsUsage is err as a usage error when it is a rejected selector
// (unknown --browser, unusable --user-data-dir): a mistyped command line, not
// a failed read, so a driver fixes the invocation instead of retrying it (exit
// 2). nil for any other error, which the caller reports its own way.
func selectorAsUsage(err error) error {
	var selector browsercookie.SelectorError
	if errors.As(err, &selector) {
		return asUsageError(err)
	}
	return nil
}

// kitCookiesExportWarnings are the stderr warnings for an --as export: state
// the caller asked for that the format cannot carry, and values the format
// rewrites. For playwright, everything a storageState cannot carry is listed
// in one place: the format is cookies plus localStorage and nothing else.
func kitCookiesExportWarnings(res browsercookie.Result, format browsercookie.Format) []string {
	var out []string
	if format == browsercookie.FormatPlaywright {
		if n := browsercookie.SessionStorageItems(res.Origins); n > 0 {
			out = append(out, fmt.Sprintf("%d sessionStorage entry/entries are not in the storageState (the format has no field for them): write them with --as playwright-init and pass the file to context.addInitScript", n))
		}
		if n := browsercookie.PartitionedOrigins(res.Origins); n > 0 {
			out = append(out, fmt.Sprintf("%d origin(s) hold partitioned third-party storage and are not in the storageState: Playwright cannot express the partition, and restoring them unpartitioned would put another site's data in the first-party bucket (they are in -j)", n))
		}
		if n := len(res.Unreadable); n > 0 {
			out = append(out, fmt.Sprintf("%d origin(s) also hold IndexedDB, which a storageState cannot carry; if the restored session still shows a login page, re-run with --clone-profile", n))
		}
	}
	if kitCookiesWithStorage && !browsercookie.FormatCarriesStorage(format) {
		out = append(out, fmt.Sprintf("--as %s carries cookies only; the %d storage entry/entries read are not in it (use --as playwright, playwright-init, json, jsonl, or -j)", format, res.StorageItems()))
	}
	if withheld := browsercookie.SameSiteNoneWithheld(res.Cookies, browsercookie.RenderOptions{SameSite: kitCookiesSameSite}); withheld > 0 {
		out = append(out, fmt.Sprintf("--same-site none was not applied to %d non-Secure cookie(s): a browser rejects SameSite=None without Secure, so they keep %s", withheld, browsercookie.DefaultSameSite))
	}
	if format == browsercookie.FormatHeader {
		if domains := browsercookie.DistinctDomains(res.Cookies); len(domains) > 1 {
			out = append(out, fmt.Sprintf("a Cookie header serves one host, but these cookies span %d domains (%s); the header mixes them", len(domains), strings.Join(domains, ", ")))
		}
	}
	return out
}

// redactKitCookiesReport returns the report with every cookie and storage
// value masked (browsercookie.Redact, through redactValue, which marks the
// envelope redacted the way every -j masking path does) when on; res's slices
// are not modified.
func redactKitCookiesReport(on bool, report kitCookiesReport) kitCookiesReport {
	if !on {
		return report
	}
	cookies := make([]browsercookie.Cookie, len(report.Cookies))
	for i, c := range report.Cookies {
		c.Value = redactValue(on, c.Value, browsercookie.Redact)
		cookies[i] = c
	}
	report.Cookies = cookies
	if report.Origins != nil {
		origins := make([]browsercookie.Origin, len(report.Origins))
		for i, o := range report.Origins {
			o.LocalStorage = redactStorageItems(on, o.LocalStorage)
			o.SessionStorage = redactStorageItems(on, o.SessionStorage)
			origins[i] = o
		}
		report.Origins = origins
	}
	return report
}

func redactStorageItems(on bool, items []browsercookie.StorageItem) []browsercookie.StorageItem {
	if items == nil {
		return nil
	}
	out := make([]browsercookie.StorageItem, len(items))
	for i, it := range items {
		it.Value = redactValue(on, it.Value, browsercookie.Redact)
		out[i] = it
	}
	return out
}

// kitCookiesExportEmpty reports whether an export in format would carry
// nothing: no cookie, and no storage the format can hold.
func kitCookiesExportEmpty(res browsercookie.Result, format browsercookie.Format) bool {
	if len(res.Cookies) > 0 {
		return false
	}
	return !browsercookie.FormatCarriesStorage(format) || res.StorageItems() == 0
}

// kitCookiesCloneSource picks which profile to clone.
//
// A clone is one browser profile — it is a user-data directory, and there is no
// such thing as a merged one. When the read spanned several, the caller has to
// say which, because picking for them would hand over a session from a profile
// they did not name.
func kitCookiesCloneSource(res browsercookie.Result) (browsercookie.StoreInfo, error) {
	var candidates []browsercookie.StoreInfo
	for _, s := range res.Stores {
		if s.Count > 0 || s.StorageOrigins > 0 {
			candidates = append(candidates, s.Store)
		}
	}
	switch len(candidates) {
	case 0:
		return browsercookie.StoreInfo{}, usageErrorf("no profile held anything to clone")
	case 1:
		return candidates[0], nil
	}
	names := make([]string, 0, len(candidates))
	for _, c := range candidates {
		names = append(names, c.Describe())
	}
	return browsercookie.StoreInfo{}, usageErrorf(
		"--clone-profile copies one profile, but %d matched (%s): narrow it with --browser and --profile",
		len(candidates), strings.Join(names, ", "))
}

// kitCookiesResolveScope reads the scope from --scope and --apex, rejecting a
// contradiction between them rather than silently preferring one.
func kitCookiesResolveScope(cmd *cobra.Command) (browsercookie.Scope, error) {
	scope, err := browsercookie.ParseScope(kitCookiesScope)
	if err != nil {
		return scope, asUsageError(err)
	}
	if !kitCookiesApex {
		return scope, nil
	}
	if cmd.Flags().Changed("scope") && scope != browsercookie.ScopeApex {
		return scope, usageErrorf("--apex and --scope %s disagree: --apex is shorthand for --scope apex", kitCookiesScope)
	}
	return browsercookie.ScopeApex, nil
}

// kitCookiesErrorCode maps a store problem to the machine error code.
func kitCookiesErrorCode(p browsercookie.Problem) apicontract.ErrorCode {
	switch p {
	case browsercookie.ProblemKeyringDenied:
		return apicontract.CodeKeyringDenied
	case browsercookie.ProblemEncryptionUnsupported:
		return apicontract.CodeBrowserEncryptionUnsupported
	default:
		return apicontract.CodeSourceUnreadable
	}
}

// kitCookiesProblemSummary states the problem in one actionable line.
func kitCookiesProblemSummary(p browsercookie.Problem) string {
	switch p {
	case browsercookie.ProblemKeyringDenied:
		return "the browser's decryption key could not be read from the OS keyring — run `vigolium kit cookies doctor` to grant access"
	case browsercookie.ProblemEncryptionUnsupported:
		return "the profile's cookies are App-Bound encrypted and cannot be read by another process"
	case browsercookie.ProblemDecryptFailed:
		return "the cookie values did not decrypt"
	default:
		return "the cookie store could not be read"
	}
}

// kitCookiesWriteSecret writes an export that contains live credentials.
//
// atomicfile owns the two properties this needs: the mode is applied at
// creation (a chmod after the write leaves a session world-readable for as long
// as it takes to run) and the write is atomic, so a failure leaves the previous
// file intact rather than a truncated storageState at the path the operator is
// about to hand to Playwright. 0600 rather than atomicfile.WriteBytes' 0644,
// because this is a credential, not a report.
func kitCookiesWriteSecret(path string, data []byte) error {
	err := atomicfile.WriteFile(path, 0o600, func(w *bufio.Writer) error {
		_, err := w.Write(data)
		return err
	})
	if err != nil {
		return codedErrorf(apicontract.CodeExportFailed, "write %s: %w", path, err)
	}
	return nil
}

// kitCookiesPrintHuman renders the listing for a terminal. Values are redacted
// unless --reveal was given: the common case is checking whether a session is
// there, which needs the cookie's name and expiry, not its value.
//
// With --as the export IS the output, so the table is suppressed. Printed
// anyway it would follow a --stdout export down the same pipe, gluing a human
// table onto the storageState or Cookie header the caller asked for.
func kitCookiesPrintHuman(report kitCookiesReport, format browsercookie.Format) {
	if report.Count > 0 && format == "" && report.Clone == nil {
		tbl := terminal.NewTableWithMaxWidth(globalWidth, "DOMAIN", "NAME", "VALUE", "LEN", "EXPIRES", "FLAGS", "PROFILE")
		now := time.Now()
		for _, c := range report.Cookies {
			tbl.AddRow(c.Domain, c.Name, kitCookiesValue(c.Value), len(c.Value),
				kitCookiesExpiry(c, now), kitCookiesFlags(c),
				c.Browser+"/"+c.ProfileName())
		}
		tbl.Print()
	}

	if len(report.Origins) > 0 && format == "" && report.Clone == nil {
		kitCookiesPrintStorage(report.Origins)
	}

	if c := report.Clone; c != nil {
		fmt.Fprintf(os.Stderr, "%s cloned %s into %s — %d cookie(s), %d localStorage + %d sessionStorage key(s), %d origin(s) of IndexedDB, %.1f MiB\n",
			terminal.InfoSymbol(), browsercookie.CloneOriginSummary(*c), c.Dir,
			c.Cookies, c.LocalStorageKeys, c.SessionStorageKeys, c.IndexedDBOrigins,
			float64(c.Bytes)/(1024*1024))
		fmt.Fprintf(os.Stderr, "%s open it with Playwright's launchPersistentContext; see %s/VIGOLIUM-README.md\n",
			terminal.InfoSymbol(), c.Dir)
		for _, w := range c.Warnings {
			fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(), w)
		}
	}

	if report.Output != "" {
		fmt.Fprintf(os.Stderr, "%s wrote %d cookie(s)%s to %s (mode 0600 — this is a live credential)\n",
			terminal.InfoSymbol(), report.Count, kitCookiesStorageSuffix(report), report.Output)
	}

	switch {
	case report.Count == 0 && report.Problem != "":
		// Not "no cookies matched": the stores could not be read, and the
		// error that follows says why. Saying "nothing matched" first is how a
		// denied keyring passed for a domain with no session.
	case report.Count == 0:
		fmt.Fprintf(os.Stderr, "%s no cookies matched %s\n", terminal.InfoSymbol(), strings.Join(report.Matched, ", "))
	case format != "" && report.Output == "" && report.OutputKept == "":
		fmt.Fprintf(os.Stderr, "%s wrote %d cookie(s) as %s to stdout — this is a live credential\n",
			terminal.InfoSymbol(), report.Count, format)
	case report.Output == "":
		fmt.Fprintf(os.Stderr, "\n%s %d cookie(s)%s for %s\n", terminal.InfoSymbol(), report.Count,
			kitCookiesStorageSuffix(report), strings.Join(report.Matched, ", "))
		if !kitCookiesReveal {
			fmt.Fprintf(os.Stderr, "%s values redacted; --as with -o writes them to a 0600 file\n", terminal.InfoSymbol())
		}
	}
	if report.OutputKept != "" {
		fmt.Fprintf(os.Stderr, "%s kept the existing %s: this read had nothing to write over it\n", terminal.WarningSymbol(), report.OutputKept)
	}

	for _, w := range report.Warnings {
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(), w)
	}
	for _, s := range report.Stores {
		if s.Problem == browsercookie.ProblemNone {
			continue
		}
		fmt.Fprintf(os.Stderr, "%s %s: %s\n", terminal.WarningSymbol(), s.Store.Describe(), kitCookiesProblemSummary(s.Problem))
	}
}

// kitCookiesPrintStorage renders the localStorage listing. Values are redacted
// on the same terms as cookie values: a storage entry routinely holds the same
// bearer token the cookie does.
func kitCookiesPrintStorage(origins []browsercookie.Origin) {
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "ORIGIN", "KIND", "KEY", "VALUE", "LEN")
	for _, o := range origins {
		for _, item := range o.LocalStorage {
			tbl.AddRow(o.Origin, "local", item.Name, kitCookiesValue(item.Value), len(item.Value))
		}
		for _, item := range o.SessionStorage {
			tbl.AddRow(o.Origin, "session", item.Name, kitCookiesValue(item.Value), len(item.Value))
		}
	}
	tbl.Print()
}

// kitCookiesValue renders a stored value for the terminal: redacted unless
// --reveal. One helper, because the cookie and storage tables made the same
// decision and a value is a credential in both.
func kitCookiesValue(value string) string {
	if kitCookiesReveal {
		return value
	}
	return browsercookie.Redact(value)
}

// kitCookiesStorageSuffix describes the storage half of an export, for the
// one-line summary.
func kitCookiesStorageSuffix(report kitCookiesReport) string {
	if len(report.Origins) == 0 {
		return ""
	}
	return fmt.Sprintf(" and %d localStorage entry/entries across %d origin(s)", report.StorageItems, len(report.Origins))
}

// kitCookiesCheckStatus maps a browsercookie check status onto the
// diagnostics vocabulary the shared doctor renderer speaks, so
// `kit cookies doctor` and `doctor` print the same symbols and colours.
func kitCookiesCheckStatus(status string) diagnostics.Status {
	switch status {
	case browsercookie.StatusOK:
		return diagnostics.StatusOK
	case browsercookie.StatusFail:
		return diagnostics.StatusError
	default:
		// warn and skip: neither is a failure, and neither is clean.
		return diagnostics.StatusWarning
	}
}

// kitCookiesExpiry renders a cookie's remaining life. A session cookie says so
// rather than showing a zero time, because "session" is the operator's cue that
// the handoff may already be dead.
func kitCookiesExpiry(c browsercookie.Cookie, now time.Time) string {
	if c.Session() {
		return "session"
	}
	if c.Expires.Before(now) {
		return "expired"
	}
	return c.Expires.Format(time.RFC3339)
}

// kitCookiesFlags renders the attributes that change how a cookie must be
// replayed.
func kitCookiesFlags(c browsercookie.Cookie) string {
	var flags []string
	if c.Secure {
		flags = append(flags, "secure")
	}
	if c.HTTPOnly {
		flags = append(flags, "httponly")
	}
	if c.SameSite != browsercookie.SameSiteUnknown {
		flags = append(flags, "samesite="+strings.ToLower(c.SameSite))
	}
	if len(flags) == 0 {
		return "-"
	}
	return strings.Join(flags, ",")
}

// kitCookiesProfilesReport is the -j payload for `profiles`.
type kitCookiesProfilesReport struct {
	Count    int                       `json:"count"`
	Profiles []browsercookie.StoreInfo `json:"profiles"`
}

func runKitCookiesProfiles(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	stores, err := browsercookie.Discover(ctx, browsercookie.Query{
		Browsers:     kitCookiesProfilesBrowsers,
		UserDataDirs: kitCookiesProfilesUserDataDirs,
	})
	if err != nil {
		return asUsageError(err)
	}
	if stores == nil {
		stores = []browsercookie.StoreInfo{}
	}

	if globalJSON {
		return emitStructRead(cmd, kitCookiesProfilesReport{Count: len(stores), Profiles: stores}, "profiles")
	}

	if len(stores) == 0 {
		fmt.Fprintf(os.Stderr, "%s no browser cookie store found; --user-data-dir points at a profile in a custom location\n", terminal.InfoSymbol())
		return nil
	}
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "BROWSER", "PROFILE", "LABEL", "ACCOUNT", "DEFAULT", "NOTES", "STORE")
	for _, s := range stores {
		var notes []string
		if s.AppBound {
			notes = append(notes, "app-bound")
		}
		if s.WAL {
			notes = append(notes, "unflushed-writes")
		}
		if s.Explicit {
			notes = append(notes, "explicit-dir")
		}
		note := "-"
		if len(notes) > 0 {
			note = strings.Join(notes, ",")
		}
		tbl.AddRow(s.Browser, firstNonEmptyString(s.Profile, "-"), firstNonEmptyString(s.Label, "-"), firstNonEmptyString(s.Account, "-"),
			yesNo(s.Default), note, s.File)
	}
	tbl.Print()
	fmt.Fprintf(os.Stderr, "\n%s %d profile(s)\n", terminal.InfoSymbol(), len(stores))
	return nil
}

func runKitCookiesDoctor(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	probeKeyring := !kitCookiesSkipKeyringProbe
	if probeKeyring {
		kitCookiesNotice(cmd)
	}

	diag, err := browsercookie.Diagnose(ctx, browsercookie.Query{
		Browsers:     kitCookiesDoctorBrowsers,
		UserDataDirs: kitCookiesDoctorUserDataDirs,
	}, probeKeyring)
	if err != nil {
		return asUsageError(err)
	}

	if globalJSON {
		if err := emitStructRead(cmd, diag, "checks"); err != nil {
			return err
		}
	} else {
		for _, c := range diag.Checks {
			printCheck(c.Name, kitCookiesCheckStatus(c.Status), c.Detail)
		}
		for _, c := range diag.Checks {
			if c.Hint == "" || c.Status == browsercookie.StatusOK {
				continue
			}
			fmt.Fprintf(os.Stderr, "\n%s %s\n  %s\n", terminal.WarningSymbol(), c.Name, c.Hint)
		}
		if diag.Ready {
			fmt.Fprintf(os.Stderr, "\n%s cookies can be read on this machine\n", terminal.InfoSymbol())
		}
	}

	if !diag.Ready {
		return codedErrorf(apicontract.CodeNotReady, "cookies cannot be read here; see the failing checks above")
	}
	return nil
}

// kitCookiesNoticePath is where the acknowledgement marker lives once the
// notice has been shown.
const kitCookiesNoticePath = "~/.vigolium/kit-cookies-ack"

// kitCookiesAcknowledged reports whether --yes or VIGOLIUM_COOKIES_ACK
// (read by utils.EnvTruthy: 1/true/yes/on) acknowledges the notice.
func kitCookiesAcknowledged() bool {
	return kitCookiesAck || utils.EnvTruthy("VIGOLIUM_COOKIES_ACK")
}

// kitCookiesNotice prints the first-run notice once per machine.
//
// It goes to stderr unconditionally — never stdout, which belongs to the
// machine-readable payload — and it says the three things an operator cannot
// discover from the output: that the OS will ask for approval, that endpoint
// security tooling commonly alerts on a process reading a browser's credential
// store, and that what comes back is a live credential rather than a report.
// The EDR line is the one worth keeping: on a managed device the alert fires,
// and someone who was warned reads it as their own tool working.
func kitCookiesNotice(cmd *cobra.Command) {
	if kitCookiesAcknowledged() {
		return
	}
	marker := config.ExpandPath(kitCookiesNoticePath)
	if marker != "" {
		if _, err := os.Stat(marker); err == nil {
			return
		}
	}

	fmt.Fprintf(os.Stderr, `%s vigolium kit cookies reads your own browser's cookie store on this machine.

  - Your OS will ask to release the browser's decryption key. On macOS choose
    "Allow" (this read only), not "Always Allow": that lets every process on
    this machine read the key, and every cookie, without asking. Nothing is
    read until you approve it.
  - Endpoint security tooling (EDR/XDR) commonly alerts on a process reading a
    browser credential store. Expect a detection, and tell your team first if
    this is a managed device.
  - What comes back is a live session, not a report. A file written with -o is
    mode 0600: do not commit it, do not paste it, and treat it as the session.

Re-run with --yes to skip this notice, or set VIGOLIUM_COOKIES_ACK=1.

`, terminal.WarningSymbol())

	// Remembering that the notice was shown is best-effort: an unwritable home
	// directory should cost a repeated notice, never the command.
	if marker != "" {
		if err := os.MkdirAll(config.ExpandPath("~/.vigolium"), 0o700); err == nil {
			_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
		}
	}
}

// yesNo renders a bool for a table cell.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
