package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func mustTranslate(t *testing.T, fn func([]string) (shimTranslation, error), args ...string) (string, shimTranslation) {
	t.Helper()
	tr, err := fn(args)
	if err != nil {
		t.Fatalf("translate %v: %v", args, err)
	}
	return strings.Join(tr.argv, " "), tr
}

func requireContains(t *testing.T, joined string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %q in: %s", w, joined)
		}
	}
}

func hasNote(tr shimTranslation, substr string) bool {
	return slices.ContainsFunc(tr.notes, func(n string) bool { return strings.Contains(n, substr) })
}

func shimSpecNamed(t *testing.T, name string) shimSpec {
	t.Helper()
	for _, s := range shimSpecs {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("no shim %q", name)
	return shimSpec{}
}

// ---------------------------------------------------------------- ffuf ----

func TestTranslateFFUFDiscoveryRouteStripsFuzzMarker(t *testing.T) {
	// FUZZ as the whole last path segment and no matchers: content discovery,
	// which brute-forces that segment by construction.
	joined, _ := mustTranslate(t, translateFFUF, "-u", "https://t/FUZZ", "-w", "words.txt", "-recursion")
	if strings.Contains(joined, "FUZZ") {
		t.Errorf("FUZZ marker survived on the discovery route: %s", joined)
	}
	requireContains(t, joined, "run discovery", "-t https://t", "--discovery-wordlist words.txt")
}

// A -w run of one last-segment FUZZ is sent word by word (fuzz), not turned
// into a discovery phase that crawls and adds its own lists.
func TestTranslateFFUFWordlistRunRoutesToFuzz(t *testing.T) {
	joined, tr := mustTranslate(t, translateFFUF, "-u", "http://h/FUZZ", "-w", "five.txt")
	if !strings.HasPrefix(joined, "fuzz http://h/FUZZ") {
		t.Errorf("wordlist run not routed to fuzz: %s", joined)
	}
	if !hasNote(tr, "-recursion") {
		t.Errorf("the discovery alternative is not named: %v", tr.notes)
	}
}

func TestTranslateFFUFMapsPaceFlags(t *testing.T) {
	joined, _ := mustTranslate(t, translateFFUF, "-u", "https://t/FUZZ", "-t", "5", "-rate", "20")
	requireContains(t, joined, "--concurrency 5", "--rate-limit 20")
}

func TestTranslateFFUFAcceptsEqualsForm(t *testing.T) {
	joined, _ := mustTranslate(t, translateFFUF, "-u=https://t/FUZZ", "-w=words.txt")
	requireContains(t, joined, "fuzz https://t/FUZZ", "-w words.txt")
}

func TestTranslateFFUFStripsWordlistKeyword(t *testing.T) {
	joined, _ := mustTranslate(t, translateFFUF, "-u", "https://t/FUZZ", "-w", "words.txt:FUZZ", "-recursion")
	requireContains(t, joined, "--discovery-wordlist words.txt")
}

func TestTranslateFFUFMidSegmentRoutesToFuzzKeepingMarker(t *testing.T) {
	// /api/FUZZ.php is not a path segment discovery can brute-force; stripping
	// the marker used to turn it into the URL /api/.php.
	joined, tr := mustTranslate(t, translateFFUF, "-u", "https://t/api/FUZZ.php", "-w", "words.txt")
	if !strings.HasPrefix(joined, "fuzz https://t/api/FUZZ.php") {
		t.Errorf("not routed to fuzz with the marker kept: %s", joined)
	}
	requireContains(t, joined, "-w words.txt")
	if !hasNote(tr, "not the whole last path segment") {
		t.Errorf("route reason not noted: %v", tr.notes)
	}
}

func TestTranslateFFUFMarkerInHeaderRoutesToFuzz(t *testing.T) {
	joined, tr := mustTranslate(t, translateFFUF, "-u", "https://t/", "-H", "X-Api: FUZZ", "-w", "w.txt")
	if !strings.HasPrefix(joined, "fuzz https://t/") {
		t.Errorf("header marker not routed to fuzz: %s", joined)
	}
	requireContains(t, joined, "-H X-Api: FUZZ")
	if !hasNote(tr, "header") {
		t.Errorf("route reason not noted: %v", tr.notes)
	}
}

func TestTranslateFFUFMatchersRouteToFuzz(t *testing.T) {
	joined, tr := mustTranslate(t, translateFFUF, "-u", "https://t/FUZZ", "-w", "w.txt", "-mc", "200,301", "-fs", "1234", "-fw", "5", "-mr", "admin")
	if !strings.HasPrefix(joined, "fuzz https://t/FUZZ") {
		t.Errorf("matchers did not route to fuzz: %s", joined)
	}
	requireContains(t, joined,
		"--match-status-code 200,301", "--exclude-size 1234", "--exclude-words 5", "--match-regex admin")
	if !hasNote(tr, "matchers") {
		t.Errorf("route reason not noted: %v", tr.notes)
	}
}

func TestTranslateFFUFFuzzRouteMapsRequestAndPace(t *testing.T) {
	joined, _ := mustTranslate(t, translateFFUF,
		"-u", "https://t/login", "-X", "POST", "-d", "user=admin&pass=FUZZ", "-w", "pw.txt",
		"-p", "0.25", "-rate", "10", "-t", "4", "-o", "out.jsonl")
	requireContains(t, joined,
		"fuzz https://t/login", "-X POST", "-d user=admin&pass=FUZZ", "--delay 250",
		"--rate-limit 10", "--concurrency 4", "-o out.jsonl")
}

func TestTranslateFFUFKeywordFromWordlist(t *testing.T) {
	joined, _ := mustTranslate(t, translateFFUF, "-u", "https://t/?id=W1", "-w", "ids.txt:W1")
	requireContains(t, joined, "fuzz https://t/?id=W1", "-w ids.txt", "--keyword W1")

	if _, err := translateFFUF([]string{"-u", "https://t/A/B", "-w", "a.txt:A", "-w", "b.txt:B"}); err == nil {
		t.Error("several keywords accepted")
	}
}

func TestTranslateFFUFExtensionsPerRoute(t *testing.T) {
	joined, _ := mustTranslate(t, translateFFUF, "-u", "https://t/FUZZ", "-w", "w.txt", "-e", ".php,.bak", "-recursion")
	requireContains(t, joined, "run discovery", "--discovery-extensions php,bak")

	joined, _ = mustTranslate(t, translateFFUF, "-u", "https://t/FUZZ", "-w", "w.txt", "-e", ".php,.bak", "-mc", "200")
	requireContains(t, joined, "fuzz https://t/FUZZ", "--suffix .php,.bak")
}

func TestTranslateFFUFRecursion(t *testing.T) {
	joined, tr := mustTranslate(t, translateFFUF, "-u", "https://t/FUZZ", "-w", "w.txt", "-recursion", "-recursion-depth", "2")
	requireContains(t, joined, "run discovery", "--discovery-max-depth 2")
	if !hasNote(tr, "recurses by default") {
		t.Errorf("-recursion approximation not noted: %v", tr.notes)
	}
	if _, err := translateFFUF([]string{"-u", "https://t/FUZZ", "-w", "w.txt", "-recursion", "-mc", "200"}); err == nil {
		t.Error("-recursion accepted on the fuzz route")
	}
	if _, err := translateFFUF([]string{"-u", "https://t/FUZZ", "-recursion-depth", "x"}); err == nil {
		t.Error("non-numeric -recursion-depth accepted")
	}
}

func TestTranslateFFUFAutoCalibrateIsNotedNotRouted(t *testing.T) {
	joined, tr := mustTranslate(t, translateFFUF, "-u", "https://t/FUZZ", "-w", "w.txt", "-ac", "-recursion")
	requireContains(t, joined, "run discovery")
	if !hasNote(tr, "-ac accepted") {
		t.Errorf("-ac not noted: %v", tr.notes)
	}
}

func TestTranslateFFUFDelayRefusedOnDiscovery(t *testing.T) {
	if _, err := translateFFUF([]string{"-u", "https://t/FUZZ", "-p", "1"}); err == nil {
		t.Error("-p accepted on the discovery route")
	}
	if _, err := translateFFUF([]string{"-u", "https://t/x", "-H", "A: FUZZ", "-w", "w", "-p", "0.1-2"}); err == nil {
		t.Error("a delay range was accepted")
	}
}

func TestShimRefusesUnknownFlagAndNamesNativeCommand(t *testing.T) {
	// A dropped flag is a scan that ran with a scope nobody chose — the exact
	// failure the shims exist to prevent — so an unmapped argument is a hard
	// error, and it has to say where to go next.
	_, err := translateFFUF([]string{"-u", "https://t/FUZZ", "-json"})
	if err == nil {
		t.Fatal("unknown flag accepted")
	}
	if !strings.Contains(err.Error(), "run discovery") || !strings.Contains(err.Error(), "vigolium fuzz --help") {
		t.Errorf("error does not name the native commands: %v", err)
	}
}

func TestTranslateFFUFRequiresTargetAndMarker(t *testing.T) {
	if _, err := translateFFUF([]string{"-w", "words.txt"}); err == nil {
		t.Error("missing -u accepted")
	}
	if _, err := translateFFUF([]string{"-u", "https://t/", "-w", "words.txt"}); err == nil {
		t.Error("a target without the FUZZ keyword accepted")
	}
	if _, err := translateFFUF([]string{"-u", "https://t/x", "-H", "A: FUZZ"}); err == nil {
		t.Error("fuzz route without -w accepted")
	}
}

func TestShimValueMissingIsAnError(t *testing.T) {
	// A flag whose value silently became "" is a scope nobody chose.
	if _, err := translateFFUF([]string{"-u"}); err == nil {
		t.Error("dangling -u accepted")
	}
}

// -------------------------------------------------------------- nuclei ----

func TestTranslateNucleiMapsSeverityAndTags(t *testing.T) {
	joined, _ := mustTranslate(t, translateNuclei, "-u", "https://t", "-severity", "high,critical", "-tags", "cve")
	requireContains(t, joined,
		"run known-issue-scan", "--known-issue-scan-severities high,critical", "--known-issue-scan-tags cve", "-t https://t")
}

func TestTranslateNucleiRequiresTarget(t *testing.T) {
	// No stdin fallback: no -u/-l is an error, not a wait on a pipe.
	_, err := translateNuclei([]string{"-severity", "high"})
	if err == nil || !strings.Contains(err.Error(), "-u or -l is required") {
		t.Fatalf("nuclei with no target: %v", err)
	}
	joined, _ := mustTranslate(t, translateNuclei, "-l", "hosts.txt")
	requireContains(t, joined, "-T hosts.txt")
}

func TestTranslateNucleiTemplatesDirAndFile(t *testing.T) {
	dir := t.TempDir()
	tdir := filepath.Join(dir, "custom")
	if err := os.Mkdir(tdir, 0o755); err != nil {
		t.Fatal(err)
	}
	tfile := filepath.Join(dir, "a.yaml")
	if err := os.WriteFile(tfile, []byte("id: a"), 0o644); err != nil {
		t.Fatal(err)
	}
	joined, tr := mustTranslate(t, translateNuclei, "-u", "https://t", "-t", tfile, "-t", tdir, "-t", "http/cves/x.yaml")
	requireContains(t, joined,
		"--known-issue-scan-templates "+tfile,
		"--known-issue-scan-templates-dir "+tdir,
		"--known-issue-scan-templates http/cves/x.yaml")
	if strings.Contains(joined, "--known-issue-scan-templates-dir "+tfile) {
		t.Errorf("a template file was passed as a directory: %s", joined)
	}
	if !hasNote(tr, "http/cves/x.yaml") {
		t.Errorf("non-local template not noted: %v", tr.notes)
	}
}

// -------------------------------------------------------------- katana ----

func TestTranslateKatanaRefusesDepth(t *testing.T) {
	// The spider is a state machine over DOM snapshots, not a depth-limited link
	// follower. Accepting -d silently would be a different crawl than asked for.
	_, err := translateKatana([]string{"-u", "https://t", "-d", "3"})
	if err == nil {
		t.Fatal("-d accepted")
	}
	if !strings.Contains(err.Error(), "--spider-max-time") {
		t.Errorf("error does not name the knob that does bound the crawl: %v", err)
	}
}

func TestTranslateKatanaListAndDuration(t *testing.T) {
	list := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(list, []byte("https://a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	joined, tr := mustTranslate(t, translateKatana, "-list", list, "-u", "https://b", "-ct", "60", "-jc", "-o", "out.txt")
	requireContains(t, joined, "-T "+list, "-t https://b", "--spider-max-time 60s", "-o out.txt")
	if !hasNote(tr, "-jc accepted") {
		t.Errorf("-jc not noted: %v", tr.notes)
	}
	joined, _ = mustTranslate(t, translateKatana, "-u", "https://b", "-ct", "5m")
	requireContains(t, joined, "--spider-max-time 5m")
}

// ----------------------------------------------------------------- gau ----

func TestTranslateGauAddsSchemeToBareDomain(t *testing.T) {
	joined, _ := mustTranslate(t, translateGau, "target.example.com")
	requireContains(t, joined, "-t https://target.example.com")
}

func TestTranslateGauSubsRelaxesScope(t *testing.T) {
	joined, tr := mustTranslate(t, translateGau, "--subs", "target.example.com")
	requireContains(t, joined, "--scope-origin=relaxed")
	if strings.Contains(joined, "--follow-subdomains") {
		t.Errorf("--subs widened the scan: %s", joined)
	}
	if !hasNote(tr, "relaxed") {
		t.Errorf("--subs approximation not noted: %v", tr.notes)
	}
}

func TestTranslateGauRequiresTarget(t *testing.T) {
	if _, err := translateGau([]string{"--subs"}); err == nil {
		t.Error("gau with no domain accepted")
	}
}

// --------------------------------------------------------------- arjun ----

func TestTranslateArjunAddsParameters(t *testing.T) {
	joined, tr := mustTranslate(t, translateArjun, "-u", "https://t/api")
	requireContains(t, joined, "fuzz", "--fuzz new-param:query", "-w params", "--anomaly", "https://t/api")
	if !hasNote(tr, "kit param-mine") {
		t.Errorf("notes do not point at kit param-mine: %v", tr.notes)
	}
}

func TestTranslateArjunMethodSelectsLocation(t *testing.T) {
	joined, _ := mustTranslate(t, translateArjun, "-u", "https://t/api", "-m", "post")
	requireContains(t, joined, "-X POST", "--fuzz new-param:body")

	joined, _ = mustTranslate(t, translateArjun, "-u", "https://t/api", "-m", "JSON")
	requireContains(t, joined, "-X POST", "-H Content-Type: application/json", "--fuzz new-param:json")

	if _, err := translateArjun([]string{"-u", "https://t/api", "-m", "XML"}); err == nil {
		t.Error("-m XML accepted")
	}
}

func TestTranslateArjunPaceAndOutput(t *testing.T) {
	joined, _ := mustTranslate(t, translateArjun, "-u", "https://t/api", "-d", "2", "--stable", "-oJ", "out.json", "-w", "my.txt", "--rate-limit", "5")
	requireContains(t, joined, "--delay 2000", "--concurrency=1", "-o out.json", "-w my.txt", "--rate-limit 5")
}

// ------------------------------------------------- globals and dry run ----

func TestSplitShimGlobalsLeadingForm(t *testing.T) {
	root := rootCmd.PersistentFlags()
	ffuf := shimSpecNamed(t, "ffuf")
	split, err := splitShimGlobals(ffuf, []string{"--db", "x.sqlite", "-j", "--dry-run", "-u", "https://t/FUZZ", "-v"}, root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(split.globals, " ") != "--db x.sqlite -j" || !split.dryRun {
		t.Errorf("globals %v dry=%v", split.globals, split.dryRun)
	}
	// -v after the foreign argv started is ffuf's, not vigolium's.
	if strings.Join(split.foreign, " ") != "-u https://t/FUZZ -v" {
		t.Errorf("foreign %v", split.foreign)
	}
}

func TestSplitShimGlobalsRespectsCollisions(t *testing.T) {
	root := rootCmd.PersistentFlags()
	// nuclei -j is nuclei's JSONL flag (translated to --json), katana -j is
	// katana's JSONL: neither may be swallowed as vigolium's -j.
	for _, tool := range []string{"nuclei", "katana"} {
		split, err := splitShimGlobals(shimSpecNamed(t, tool), []string{"-j", "-u", "https://t"}, root)
		if err != nil {
			t.Fatal(err)
		}
		if len(split.globals) != 0 || split.foreign[0] != "-j" {
			t.Errorf("%s: -j consumed as a vigolium global: %+v", tool, split)
		}
	}
}

func TestSplitShimGlobalsSeparatorForm(t *testing.T) {
	root := rootCmd.PersistentFlags()
	split, err := splitShimGlobals(shimSpecNamed(t, "nuclei"), []string{"-j", "--proxy", "http://p:8080", "--", "-u", "https://t", "--dry-run"}, root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(split.globals, " ") != "-j --proxy http://p:8080" {
		t.Errorf("globals %v", split.globals)
	}
	if strings.Join(split.foreign, " ") != "-u https://t" || !split.dryRun {
		t.Errorf("foreign %v dry=%v", split.foreign, split.dryRun)
	}
	if _, err := splitShimGlobals(shimSpecNamed(t, "ffuf"), []string{"-u", "x", "--", "-w", "y"}, root); err == nil {
		t.Error("a foreign flag before -- accepted")
	}
	if _, err := splitShimGlobals(shimSpecNamed(t, "ffuf"), []string{"--db"}, root); err == nil {
		t.Error("a valueless --db accepted")
	}
}

// shimDryRunOutput runs the shim RunE's dry-run path (split → translate →
// emit) and returns stdout. It drives the pieces rather than rootCmd.Execute so
// the parsed globals (-j) do not leak into later tests through package state.
func shimDryRunOutput(t *testing.T, tool string, jsonMode bool, args ...string) string {
	t.Helper()
	spec := shimSpecNamed(t, tool)
	split, err := splitShimGlobals(spec, args, rootCmd.PersistentFlags())
	if err != nil {
		t.Fatal(err)
	}
	if !split.dryRun {
		t.Fatal("--dry-run not recognised")
	}
	tr, err := spec.translate(split.foreign)
	if err != nil {
		t.Fatal(err)
	}
	display := append(append([]string{}, split.globals...), tr.argv...)
	prior := globalJSON
	globalJSON = jsonMode
	t.Cleanup(func() { globalJSON = prior })
	cmd, _, err := rootCmd.Find([]string{tool})
	if err != nil {
		t.Fatal(err)
	}
	return captureStdout(t, func() {
		if err := emitShimDryRun(cmd, tool, args, display, tr.notes); err != nil {
			t.Error(err)
		}
	})
}

func TestShimDryRunJSONEnvelope(t *testing.T) {
	out := shimDryRunOutput(t, "ffuf", true, "-j", "--dry-run", "-u", "https://t/api/FUZZ.php", "-w", "w.txt", "-mc", "200")
	var env struct {
		OK    bool `json:"ok"`
		Items []struct {
			Tool          string   `json:"tool"`
			Argv          []string `json:"argv"`
			Translated    []string `json:"translated"`
			NativeCommand string   `json:"native_command"`
			Notes         []string `json:"notes"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, out)
	}
	if !env.OK || len(env.Items) != 1 {
		t.Fatalf("envelope: %s", out)
	}
	it := env.Items[0]
	if it.Tool != "ffuf" || it.Translated[0] != "-j" || !slices.Contains(it.Translated, "fuzz") {
		t.Errorf("item: %+v", it)
	}
	if !strings.HasPrefix(it.NativeCommand, "vigolium -j fuzz https://t/api/FUZZ.php") {
		t.Errorf("native_command: %s", it.NativeCommand)
	}
	if len(it.Notes) == 0 {
		t.Error("route reason missing from notes")
	}
}

func TestShimDryRunHuman(t *testing.T) {
	out := shimDryRunOutput(t, "gau", false, "--dry-run", "--subs", "example.com")
	if !strings.Contains(out, "vigolium run external-harvest --scope-origin=relaxed -t https://example.com") {
		t.Errorf("human dry run: %s", out)
	}
	if !strings.Contains(out, "# note:") {
		t.Errorf("notes not printed: %s", out)
	}
}

// ----------------------------------------------------------- help table ----

func TestShimFlagTableCoversEveryRule(t *testing.T) {
	// The --help table is generated from the same rule map translate drives,
	// so every accepted spelling must appear in it with a description.
	for _, spec := range shimSpecs {
		table := renderShimFlagTable(spec)
		for name, rule := range spec.rules() {
			spelled := "-" + name
			if len(name) > 1 {
				spelled = spec.longDash + name
			}
			if !strings.Contains(table, spelled) {
				t.Errorf("%s: %s missing from the flag table", spec.name, spelled)
			}
			if rule.describe() == "" {
				t.Errorf("%s: %s has no description", spec.name, spelled)
			}
		}
		cmd, _, err := rootCmd.Find([]string{spec.name})
		if err != nil || !strings.Contains(cmd.Long, table) {
			t.Errorf("%s: --help does not carry the generated flag table", spec.name)
		}
	}
}

func TestFlagNameNormalizesDashesAndEquals(t *testing.T) {
	for in, want := range map[string]string{
		"-u":        "u",
		"--url":     "url",
		"-u=x":      "u",
		"--url=x":   "url",
		"-severity": "severity",
	} {
		if got := flagName(in); got != want {
			t.Errorf("flagName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Types the dns command cannot resolve, and host <IP>, are refused rather
// than turned into an A lookup.
func TestDNSShimsRefuseWhatTheyCannotMap(t *testing.T) {
	for _, args := range [][]string{{"localhost", "SRV"}, {"example.com", "ptr"}, {"example.com", "NAPTR"}} {
		if _, err := translateDig(args); err == nil {
			t.Errorf("dig %v accepted", args)
		}
	}
	if tr, err := translateDig([]string{"example.com", "MX"}); err != nil || !slices.Contains(tr.argv, "mx") {
		t.Errorf("dig MX: %v %v", tr.argv, err)
	}
	for _, ip := range []string{"127.0.0.1", "::1"} {
		if _, err := translateHost([]string{ip}); err == nil {
			t.Errorf("host %s accepted", ip)
		}
	}
	if _, err := translateHost([]string{"example.com"}); err != nil {
		t.Errorf("host example.com: %v", err)
	}
}
