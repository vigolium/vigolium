//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
)

// The runtime half of the machine contract (plan B §1.3 test 4). The static
// test (pkg/cli/machine_contract_test.go) checks every command DECLARES a -j
// kind; this one runs every leaf through the real binary and checks it
// PRODUCES one: exactly one JSON document on stdout, schema_version, command
// == the cobra path, ok, kind, `changed` on a mutation, `items` an array. A
// second run per leaf with an unknown flag must print one usage_error document
// and exit 2.
//
// Every leaf of the command tree has a row, with minimal arguments or an
// explicit skip reason; a leaf missing from the table (or a row naming no
// leaf) fails the test, so a new command cannot ship without a row. Each row
// runs in its own copy of a seeded HOME and database, so mutations cannot
// disturb one another. Network: local httptest servers only.

// contractRow is one leaf of the command tree.
type contractRow struct {
	// args follow the command path; -j is appended. Placeholders: {T} the local
	// target's base URL, {F} the shared fixture-file directory, {DIR} the row's
	// own scratch directory.
	args []string
	// skip, when set, is why the happy-path run cannot happen here; the
	// bad-flag run still does unless badFlagSkip is set too.
	skip        string
	badFlagSkip string
	// exit is the expected exit code of the happy-path run (default 0).
	exit int
	// command is the expected `command` when it is not the cobra path: a bare
	// group that is the documented shorthand for a subcommand names the
	// subcommand whose output (and schema) it prints.
	command string
	// kind overrides the envelope kind derived from the declared kind.
	kind string
	// agent runs the row with a config pointing olium at the local LLM stub.
	agent bool
	stdin string
	env   []string
}

const (
	interactive = "interactive: exempt from the -j contract (help, completion, TUI, server, passthrough shim)"
	needsS3     = "needs S3-compatible object storage"

	seedScan1   = "scan-0001-aaaa-bbbb-cccc-ddddeeee0001"
	seedScan2   = "scan-0002-aaaa-bbbb-cccc-ddddeeee0002"
	seedProject = "proj-0004-aaaa-bbbb-cccc-ddddeeee0004"
	seedRecord  = "rec-0058-seed-aaaa-bbbb-cccc003a"
	seedFinding = "11"
	// jwt.io's example token, HS256-signed with "your-256-bit-secret".
	sampleJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

// machineContractRows: one row per leaf, keyed by cobra path ("" = root).
var machineContractRows = map[string]contractRow{
	// Help, completion, TUIs, the server and the passthrough shims.
	"":                      {skip: interactive, badFlagSkip: interactive},
	"help":                  {skip: interactive, badFlagSkip: interactive},
	"kit":                   {skip: interactive, badFlagSkip: interactive},
	"kit oast":              {skip: interactive, badFlagSkip: interactive},
	"oast":                  {skip: interactive, badFlagSkip: interactive},
	"auth":                  {skip: interactive, badFlagSkip: interactive},
	"completion":            {skip: interactive, badFlagSkip: interactive},
	"config":                {skip: interactive, badFlagSkip: interactive},
	"db":                    {skip: interactive, badFlagSkip: interactive},
	"project":               {skip: interactive, badFlagSkip: interactive},
	"server ca":             {skip: interactive, badFlagSkip: interactive},
	"storage":               {skip: interactive, badFlagSkip: interactive},
	"completion bash":       {skip: interactive, badFlagSkip: interactive},
	"completion fish":       {skip: interactive, badFlagSkip: interactive},
	"completion powershell": {skip: interactive, badFlagSkip: interactive},
	"completion zsh":        {skip: interactive, badFlagSkip: interactive},
	"agent olium":           {skip: interactive, badFlagSkip: interactive},
	"olium":                 {skip: interactive, badFlagSkip: interactive},
	"server":                {skip: interactive, badFlagSkip: interactive},
	"arjun":                 {skip: interactive, badFlagSkip: interactive},
	"ffuf":                  {skip: interactive, badFlagSkip: interactive},
	"gau":                   {skip: interactive, badFlagSkip: interactive},
	"katana":                {skip: interactive, badFlagSkip: interactive},
	"nuclei":                {skip: interactive, badFlagSkip: interactive},
	"skills gen-flags":      {skip: interactive, badFlagSkip: interactive},
	"dig":                   {skip: interactive, badFlagSkip: interactive},
	"host":                  {skip: interactive, badFlagSkip: interactive},

	// Scans.
	"scan":         {args: []string{"-t", "{T}/", "--dry-run"}},
	"run":          {args: []string{"discovery", "-t", "{T}/", "--dry-run"}},
	"scan-url":     {args: []string{"-t", "{T}/search?q=1", "-m", "error-message-detect"}},
	"scan-request": {args: []string{"-i", "{F}/request.txt", "-t", "{T}", "-m", "error-message-detect"}},
	"scan diff":    {args: []string{seedScan1, seedScan2}},
	"scan status":  {args: []string{seedScan1}},
	"scan wait":    {args: []string{seedScan1}},

	// Agent (local OpenAI-compatible stub; no real LLM).
	"agent":         {args: []string{"--list-agents"}, agent: true},
	"agent query":   {args: []string{"say hi"}, agent: true},
	"agent session": {agent: true},
	"agent triage":  {args: []string{seedFinding, "--no-write", "--no-probe"}, agent: true},
	"agent autopilot": {args: []string{"-t", "{T}/", "--no-prescan", "--no-skill-filter", "--prior-context", "off",
		"--max-duration", "30s"}, agent: true},
	"agent swarm": {args: []string{"-t", "{T}/", "--dry-run"}, agent: true},
	"agent audit": {skip: "needs the vigolium-audit harness and a coding-agent CLI (claude/codex)"},
	"audit":       {skip: "needs the vigolium-audit harness and a coding-agent CLI (claude/codex)"},

	// Auth.
	"auth check": {args: []string{"{F}/session.yaml", "--url", "{T}/private"}},
	"auth lint":  {args: []string{"{F}/session.yaml"}},
	"auth list":  {},
	"auth load":  {args: []string{"{F}/session.yaml", "--host", "127.0.0.1"}},
	"auth totp":  {env: []string{"VIGOLIUM_TOTP_SECRET=JBSWY3DPEHPK3PXP"}},

	// Config.
	"config clean":    {args: []string{"--force"}},
	"config env":      {},
	"config ls":       {},
	"config set":      {args: []string{"dynamic-assessment.extensions.enabled", "true"}},
	"config validate": {},

	// Database.
	"db clean":   {args: []string{"--host", "nothing.example"}},
	"db compact": {args: []string{"--force"}},
	"db export":  {args: []string{"-o", "{DIR}/records.jsonl"}},
	"db list":    {},
	"db migrate": {},
	"db reset":   {args: []string{"--force"}},
	"db seed":    {args: []string{"--force"}},
	"db stats":   {},

	"doctor": {},
	"export": {args: []string{"-o", "{DIR}/all.jsonl"}},

	// Extensions.
	"extensions":         {command: "extensions ls"},
	"extensions docs":    {args: []string{"sha256"}},
	"extensions eval":    {args: []string{"1+1"}},
	"extensions run":     {args: []string{"--ext", "{F}/ext.js", "--record-uuid", seedRecord}},
	"extensions test":    {args: []string{"{F}/ext.js"}},
	"extensions example": {args: []string{"yaml"}},
	"extensions lint":    {args: []string{"{F}/ext.js"}},
	"extensions ls":      {},
	"extensions preset":  {},
	"extensions types":   {},

	// Findings and traffic.
	"finding":         {args: []string{"-n", "1"}},
	"finding load":    {args: []string{"{F}/findings.json"}},
	"finding mark":    {args: []string{seedFinding, "--as", "false_positive"}},
	"finding verify":  {args: []string{seedFinding, "--dry-run"}},
	"traffic":         {args: []string{"-n", "1"}},
	"traffic body":    {args: []string{"--uuid", seedRecord}},
	"traffic headers": {args: []string{"--uuid", seedRecord}},
	"endpoints":       {},
	"hosts":           {},
	"params":          {},
	"fuzz":            {args: []string{"-i", "{T}/search?q=FUZZ", "-p", "a", "-p", "b"}},
	"fingerprint":     {args: []string{"-t", "{T}/"}},
	"dns":             {skip: "needs the network: queries a DNS resolver"},
	"replay":          {args: []string{"-i", "{T}/search?q=1"}},

	// Input.
	"import": {args: []string{"{F}/import.jsonl"}},
	"ingest": {args: []string{"-I", "urls", "-i", "{F}/urls.txt"}},
	"init":   {},
	"js":     {args: []string{"--code", "1+1"}},

	"oast ingest":     {args: []string{"{F}/oast.log", "--format", "raw-log"}},
	"oast poll":       {args: []string{"--open", "--wait", "1s"}},
	"match-not-found": {stdin: `{"id":"r1","url":"http://127.0.0.1:1/x","status":404}` + "\n"},

	// Kit.
	"kit harvest":     {skip: "needs the network: queries public URL archives (wayback, commoncrawl, …)"},
	"kit js-beautify": {args: []string{"{F}/app.js"}},
	"kit jwt-crack":   {args: []string{sampleJWT}},
	"kit oast new":    {skip: "needs an interactsh server"},
	"kit oast poll":   {skip: "needs an interactsh server"},
	"kit param-mine":  {args: []string{"-t", "{T}/search"}},
	"kit payload":     {},
	"kit secret-scan": {args: []string{"{F}/app.js"}},
	"kit tmp-clean":   {},
	"kit wordlist":    {},

	// Logs.
	"log":    {args: []string{seedScan1}},
	"log ls": {},

	// Modules.
	"module":         {},
	"module ls":      {},
	"module enable":  {args: []string{"error-message-detect"}},
	"module disable": {args: []string{"error-message-detect"}},

	// Projects.
	"project config": {},
	"project create": {args: []string{"b8-matrix"}},
	"project delete": {args: []string{seedProject, "--force"}},
	"project list":   {},
	"project use":    {args: []string{seedProject}},

	// Scope.
	"scope":      {command: "scope view"},
	"scope set":  {args: []string{"host.exclude", "*.internal.example"}},
	"scope view": {},

	// The ingestion server's MITM CA.
	"server ca install":   {skip: "modifies the operating system's trust store"},
	"server ca path":      {},
	"server ca print":     {},
	"server ca uninstall": {skip: "modifies the operating system's trust store"},

	// Skills.
	"skills":         {},
	"skills get":     {args: []string{"vigolium-scanner"}},
	"skills install": {args: []string{"--dir", "{DIR}/skills"}},
	"skills list":    {},

	// Storage.
	"storage download": {skip: needsS3},
	"storage ls":       {skip: needsS3},
	"storage presign":  {skip: needsS3},
	"storage results":  {skip: needsS3},
	"storage rm":       {skip: needsS3},
	"storage upload":   {skip: needsS3},

	// Schemas.
	"schema":         {},
	"schema list":    {},
	"schema command": {args: []string{"finding"}},
	"schema event":   {},
	"schema error":   {},
	"schema plan":    {},
	"schema all":     {},
	"schema flags":   {args: []string{"scan"}},
	"schema storage": {},

	"strategy": {},
	// Verbs added beside the existing commands.
	"agent cancel":    {skip: "the seeded run ids are not hex UUIDs, which the run resolver requires; covered by agent_cancel_test.go"},
	"scan stop":       {skip: "the seeded scan ids are not hex UUIDs, which the run resolver requires; covered by scan_stop_test.go"},
	"server stop":     {skip: "needs a running server (its pidfile)"},
	"server status":   {},
	"status":          {},
	"scan ls":         {},
	"auth show":       {args: []string{"admin"}},
	"auth rm":         {args: []string{"admin", "--dry-run"}},
	"config get":      {args: []string{"oast.enabled"}},
	"config unset":    {args: []string{"oast.enabled"}},
	"finding show":    {args: []string{seedFinding}},
	"module show":     {args: []string{"xss-light-url-params"}},
	"project current": {},
	"project rename":  {args: []string{seedProject, "b8-renamed"}},
	"scope add":       {args: []string{"host", "b8.example"}},
	"scope rm":        {args: []string{"host", "b8.example"}},
	"scope check":     {args: []string{"{T}/"}},
	"update":          {skip: "needs the network: checks the release server"},
	"version":         {},
}

// TestMachineContractMatrixCoversEveryLeaf: the table and the command tree
// name the same commands. Cheap, so it runs even where the matrix is filtered.
func TestMachineContractMatrixCoversEveryLeaf(t *testing.T) {
	declared := cli.MachineContractCommands()
	var missing, stale []string
	for path := range declared {
		if _, ok := machineContractRows[path]; !ok {
			missing = append(missing, fmt.Sprintf("%q (%s)", path, declared[path]))
		}
	}
	for path := range machineContractRows {
		if _, ok := declared[path]; !ok {
			stale = append(stale, fmt.Sprintf("%q", path))
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	require.Empty(t, missing, "leaves with no row in machineContractRows: add one (minimal args, or a skip reason)")
	require.Empty(t, stale, "rows naming no command: delete them")
	for path, row := range machineContractRows {
		if declared[path] == "interactive" {
			require.NotEmpty(t, row.skip, "%q is interactive: its row must say so", path)
		}
	}
}

// TestMachineContractMatrix runs every row: the happy path and a bad flag.
func TestMachineContractMatrix(t *testing.T) {
	fx := newContractFixture(t)
	declared := cli.MachineContractCommands()
	shaped := cli.ShapedCommands()

	paths := make([]string, 0, len(machineContractRows))
	for path := range machineContractRows {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		row := machineContractRows[path]
		kind := declared[path]
		name := path
		if name == "" {
			name = "(root)"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Run("bad flag", func(t *testing.T) {
				if row.badFlagSkip != "" {
					t.Skip(row.badFlagSkip)
				}
				r := fx.run(t, path, row, []string{"--b8-no-such-flag"}, false)
				require.Equalf(t, apicontract.ExitUsageError, r.code, "an unknown flag is a usage error (exit 2)\n%s", r)
				doc := oneContractDocument(t, r)
				requireOutcomeMatchesExit(t, r, doc)
				require.Equalf(t, path, doc["command"], "%s", r)
				errObj, _ := doc["error"].(map[string]any)
				require.NotNilf(t, errObj, "the error envelope carries error{}\n%s", r)
				require.Equalf(t, "usage_error", errObj["code"], "%s", r)
			})
			// The shaping guardrail: every shaped read refuses an unknown
			// --fields name with a usage error, before it sends anything.
			t.Run("bogus fields", func(t *testing.T) {
				if _, ok := shaped[path]; !ok {
					t.Skip("not a shaped command")
				}
				if row.skip != "" {
					t.Skip(row.skip)
				}
				args := append(slices.Clone(row.args), "--fields", "b8-bogus-field")
				r := fx.run(t, path, row, args, true)
				require.Equalf(t, apicontract.ExitUsageError, r.code, "an unknown --fields name is a usage error (exit 2)\n%s", r)
				doc := oneContractDocument(t, r)
				errObj, _ := doc["error"].(map[string]any)
				require.NotNilf(t, errObj, "%s", r)
				require.Equalf(t, "usage_error", errObj["code"], "%s", r)
			})
			t.Run("happy path", func(t *testing.T) {
				if row.skip != "" {
					t.Skip(row.skip)
				}
				r := fx.run(t, path, row, row.args, true)
				require.Equalf(t, row.exit, r.code, "exit code\n%s", r)
				doc := oneContractDocument(t, r)
				wantCommand := path
				if row.command != "" {
					wantCommand = row.command
				}
				require.EqualValuesf(t, apicontract.SchemaVersion, doc["schema_version"], "%s", r)
				require.Equalf(t, wantCommand, doc["command"], "command must be the cobra path\n%s", r)
				requireOutcomeMatchesExit(t, r, doc)
				wantKind := envelopeKind(kind)
				if row.kind != "" {
					wantKind = row.kind
				}
				require.Equalf(t, wantKind, doc["kind"], "kind (declared %s)\n%s", kind, r)
				if wantKind == "mutation" {
					require.Containsf(t, doc, "changed", "a mutation says whether it changed state\n%s", r)
					require.NotEmptyf(t, doc["action"], "%s", r)
				}
				_, isArray := doc["items"].([]any)
				require.Truef(t, isArray, "items must be an array, got %T\n%s", doc["items"], r)
				requireSafeFollowUp(t, r, doc)
				// Schema coverage: a registered command's document validates. A
				// --dry-run prints the plan document instead (`schema plan`),
				// which scan_dry_run_test.go validates.
				if _, ok := contract.LookupCommand(wantCommand); ok && !slices.Contains(row.args, "--dry-run") {
					contracttest.Validate(t, wantCommand, []byte(r.stdout))
				}
			})
		})
	}
}

// requireOutcomeMatchesExit is the outcome guardrail: ok is true exactly when
// the process exited 0, 3 or 4, and error{code,message,exit_code} is present
// exactly when ok is false, naming the same exit code.
func requireOutcomeMatchesExit(t *testing.T, r contractRun, doc map[string]any) {
	t.Helper()
	wantOK := r.code == apicontract.ExitSuccess || r.code == apicontract.ExitFuzzMatch || r.code == apicontract.ExitFailOnGate
	require.Equalf(t, wantOK, doc["ok"], "ok must be true exactly when exit is 0, 3 or 4\n%s", r)
	errObj, hasErr := doc["error"].(map[string]any)
	require.Equalf(t, !wantOK, hasErr, "error must be present exactly when ok is false\n%s", r)
	if hasErr {
		require.NotEmptyf(t, errObj["code"], "%s", r)
		require.EqualValuesf(t, r.code, errObj["exit_code"], "error.exit_code is the process exit code\n%s", r)
	}
}

// requireSafeFollowUp is the hint guardrail: a query_argv parses, names a read
// that sends no traffic, and repeats the source's --db.
func requireSafeFollowUp(t *testing.T, r contractRun, doc map[string]any) {
	t.Helper()
	raw, ok := doc["query_argv"].([]any)
	if !ok {
		return
	}
	argv := make([]string, 0, len(raw))
	for _, a := range raw {
		argv = append(argv, fmt.Sprint(a))
	}
	sourceDB := ""
	for i, a := range r.argv {
		if a == "--db" && i+1 < len(r.argv) {
			sourceDB = r.argv[i+1]
		}
	}
	require.NoErrorf(t, cli.CheckFollowUpArgv(nil, argv, sourceDB), "%s", r)
}

// envelopeKind is the `kind` a declared kind renders: a stream command's -j
// document is a read envelope (its stream needs an explicit flag).
func envelopeKind(declared string) string {
	if declared == "stream" {
		return "read"
	}
	return declared
}

// contractFixture is one seeded template install, copied per row, plus the
// local target, the LLM stub and the shared input files.
type contractFixture struct {
	bin, tmpl, files string
	target           *httptest.Server
	llm              *stubLLM
}

func newContractFixture(t *testing.T) *contractFixture {
	t.Helper()
	fx := &contractFixture{bin: buildVigoliumBinary(t), tmpl: t.TempDir(), files: t.TempDir(), llm: newStubLLM(t)}
	// A triage verdict; agent query prints whatever comes back.
	fx.llm.reply.Store(`{"verdict":"false_positive","reasoning":"static content"}`)

	mux := http.NewServeMux()
	// /private tells a credentialed request (the auth rows' session) from an
	// anonymous one.
	mux.HandleFunc("/private", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "b8-key" {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, "<html><body>welcome back, b8</body></html>")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<html><head><title>b8</title></head><body><a href="/search?q=1">search</a>`+
			`<form action="/search"><input name="q"></form><p>%s</p></body></html>`, r.URL.Query().Get("q"))
	})
	fx.target = httptest.NewServer(mux)
	t.Cleanup(fx.target.Close)

	for name, body := range map[string]string{
		"session.yaml": "sessions:\n  - name: b8\n    role: primary\n    headers:\n      X-Api-Key: b8-key\n",
		"ext.js": `module.exports = {
  id: "b8-ext", name: "B8 extension", type: "passive", severity: "info",
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) { return null; }
};
`,
		"app.js":       "var a=1;function f(){return a+1}\n",
		"import.jsonl": `{"type":"finding","data":{"module_id":"mod-b8","module_name":"B8","severity":"low","confidence":"firm","finding_hash":"b8-hash","url":"` + fx.target.URL + `/","hostname":"127.0.0.1"}}` + "\n",
		"findings.json": `{"findings":[{"title":"B8 finding","severity":"low","url":"` + fx.target.URL +
			`/search","description":"loaded by the contract matrix"}]}` + "\n",
		"urls.txt":    fx.target.URL + "/search?q=1\n",
		"oast.log":    "2026-10-10T00:00:00Z GET /b8 from 127.0.0.1\n",
		"request.txt": "GET /search?q=1 HTTP/1.1\r\nHost: " + strings.TrimPrefix(fx.target.URL, "http://") + "\r\n\r\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(fx.files, name), []byte(body), 0o600))
	}

	// The template: first-run initialization and the sample data, once.
	home := filepath.Join(fx.tmpl, "home")
	require.NoError(t, os.MkdirAll(home, 0o755))
	r := fx.exec(t, home, filepath.Join(fx.tmpl, "db.sqlite"), nil, "",
		"--skip-dependency-check", "db", "seed", "-j")
	require.Equalf(t, 0, r.code, "seed the template database\n%s", r)
	// No interactsh registration or DNS probe from any row (doctor, scans):
	// the only server a row may reach is the local target.
	r = fx.exec(t, home, filepath.Join(fx.tmpl, "db.sqlite"), nil, "", "config", "set", "oast.enabled", "false", "-j")
	require.Equalf(t, 0, r.code, "disable OAST in the template config\n%s", r)
	return fx
}

// contractRun is one invocation's outcome.
type contractRun struct {
	argv           []string
	code           int
	stdout, stderr string
}

func (r contractRun) String() string {
	return fmt.Sprintf("argv: %q\nexit: %d\nstdout:\n%s\nstderr:\n%s", r.argv, r.code, clip(r.stdout), clip(r.stderr))
}

func clip(s string) string {
	if len(s) > 4000 {
		return s[:4000] + "…"
	}
	return s
}

// run executes one row in a fresh copy of the template install.
func (fx *contractFixture) run(t *testing.T, path string, row contractRow, args []string, happy bool) contractRun {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	require.NoError(t, copyTree(filepath.Join(fx.tmpl, "home"), home))
	db := filepath.Join(dir, "db.sqlite")
	require.NoError(t, copyTree(filepath.Join(fx.tmpl, "db.sqlite"), db))

	var argv []string
	if row.agent {
		cfg := filepath.Join(dir, "agent-config.yaml")
		require.NoError(t, os.WriteFile(cfg, []byte(fmt.Sprintf(`agent:
  sessions_dir: %s
  olium:
    provider: openai-compatible
    model: stub-model
    preflight_timeout: 10s
    custom_provider:
      base_url: %s/v1
      model_id: stub-model
`, filepath.Join(home, "agent-sessions"), fx.llm.srv.URL)), 0o600))
		argv = append(argv, "--config", cfg)
	}
	if path != "" {
		argv = append(argv, strings.Fields(path)...)
	}
	replacer := strings.NewReplacer("{T}", fx.target.URL, "{F}", fx.files, "{DIR}", dir)
	for _, a := range args {
		argv = append(argv, replacer.Replace(a))
	}
	argv = append(argv, "-j")
	stdin := ""
	if happy {
		stdin = row.stdin
	}
	return fx.exec(t, home, db, row.env, stdin, argv...)
}

func (fx *contractFixture) exec(t *testing.T, home, db string, env []string, stdin string, args ...string) contractRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	argv := append([]string{"--db", db}, args...)
	cmd := exec.CommandContext(ctx, fx.bin, argv...)
	cmd.Env = contractEnv(home, env)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %q: %v\nstderr: %s", argv, err, stderr.String())
	}
	return contractRun{argv: argv, code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// contractEnv is the parent environment minus anything that could pick a
// store, a project or a proxy for the child, plus an isolated HOME.
func contractEnv(home string, extra []string) []string {
	env := []string{"HOME=" + home, "NO_COLOR=1", "VIGOLIUM_DISABLE_UPDATE_CHECK=1"}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "HOME", strings.HasPrefix(name, "VIGOLIUM_"),
			strings.EqualFold(name, "http_proxy"), strings.EqualFold(name, "https_proxy"),
			strings.EqualFold(name, "all_proxy"):
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// oneContractDocument decodes stdout as exactly one JSON object.
func oneContractDocument(t *testing.T, r contractRun) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(r.stdout))
	var doc map[string]any
	require.NoErrorf(t, dec.Decode(&doc), "stdout must be one JSON document\n%s", r)
	var extra json.RawMessage
	require.ErrorIsf(t, dec.Decode(&extra), io.EOF, "stdout carries a second document\n%s", r)
	return doc
}

// copyTree copies a file or a directory tree.
func copyTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return copyFile(src, dst, info.Mode())
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		return copyFile(p, target, fi.Mode())
	})
}

func copyFile(src, dst string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
