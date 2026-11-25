package cli

import (
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/internal/runner"
)

// commandReach declares, per command path, which argv words name a target and
// how far the command reaches, for `schema commands -j` (targets, reach,
// reach_flags) and `explain-argv`. A guard in front of vigolium reads these
// instead of keeping its own tables of target positions, phase aliases and
// no-request subcommands.
//
// Reach levels, narrowest first:
//
//   - none: nothing is sent to a target (a store read or write, a print, a
//     resolver or archive lookup, an OAST poll).
//   - line: only the targets the line names, directly or in a file or input
//     it names, and what the run finds from them within scope.
//   - store: targets drawn from the store — rows the line names by id
//     (record, finding, scan) or the stored records of the hosts it names.
//   - unbounded: hosts no word of the line names: every stored record, an
//     agent or a script choosing its own destinations, a server scanning what
//     it receives.
//
// ReachFlags refine Reach: each entry whose flag is set (and whose With
// flag, when named, is set too) replaces the reach, in table order, so the
// last applicable entry wins. --help, -h, --usage and --dry-run reach none
// on every command (globalReachFlags). A command absent here reaches none and
// names no target; TestCommandReachCoversTraffic fails on a traffic-sending
// command that is absent, and on a flag named here that the command lacks.
var commandReach = map[string]reachTrait{
	"scan": {
		Reach: reachStore,
		Targets: []targetSpec{
			{Positional: positionalEach, Kind: targetURL},
			{Flag: "target", Kind: targetURL},
			{Flag: "target-file", Kind: targetFile},
			{Flag: "input", Kind: targetInput},
			{Flag: "record-uuid", Kind: targetRecordUUID},
			{Flag: "only-new-since", Kind: targetScanUUID},
			{Flag: "resume-scan", Kind: targetScanUUID},
		},
		// `scan -t` names an origin: it also tests the records already stored
		// for its hosts unless --input-only.
		ReachFlags: []reachFlag{
			{Flag: "input-only", Reach: reachLine},
			{Flag: "record-uuid", Reach: reachStore},
			{Flag: "only-new-since", Reach: reachStore},
			{Flag: "resume-scan", Reach: reachStore},
			{Flag: "all-records", Reach: reachUnbounded},
		},
	},
	"run": {
		Reach: reachLine,
		Targets: []targetSpec{
			{Flag: "target", Kind: targetURL},
			{Flag: "target-file", Kind: targetFile},
			{Flag: "input", Kind: targetInput},
			{Flag: "resume-scan", Kind: targetScanUUID},
		},
		ReachFlags: []reachFlag{
			{Flag: "include-stored", Reach: reachStore},
			{Flag: "resume-scan", Reach: reachStore},
			{Flag: "all-records", Reach: reachUnbounded},
		},
		Note: "the positional is the phase, never a target",
	},
	"scan-url": {
		Reach:      reachLine,
		Targets:    []targetSpec{{Positional: positionalFirst, Kind: targetURL}, {Flag: "target", Kind: targetURL}},
		ReachFlags: []reachFlag{{Flag: "include-stored", Reach: reachStore}},
	},
	"scan-request": {
		Reach:      reachLine,
		Targets:    []targetSpec{{Flag: "input", Kind: targetInput}, {Flag: "target", Kind: targetURL, Pins: true}},
		ReachFlags: []reachFlag{{Flag: "include-stored", Reach: reachStore}},
	},
	"fingerprint": {
		Reach: reachLine,
		Targets: []targetSpec{
			{Positional: positionalEach, Kind: targetURL},
			{Flag: "target", Kind: targetURL},
			{Flag: "target-file", Kind: targetFile},
			{Flag: "input", Kind: targetInput},
		},
	},
	"fuzz": {
		Reach: reachLine,
		Targets: []targetSpec{
			{Positional: positionalFirst, Kind: targetURL},
			{Flag: "target", Kind: targetURL, Pins: true},
			{Flag: "input", Kind: targetInput},
			{Flag: "input-file", Kind: targetFile},
			{Flag: "record-uuid", Kind: targetRecordUUID},
		},
		ReachFlags: []reachFlag{{Flag: "record-uuid", Reach: reachStore}},
		Note:       "--target overrides the scheme, host and port the request is sent to",
	},
	"replay": {
		Reach: reachStore,
		Targets: []targetSpec{
			{Flag: "record-uuid", Kind: targetRecordUUID},
			{Flag: "finding-id", Kind: targetFindingID},
			{Flag: "host", Kind: targetHost},
			{Flag: "target", Kind: targetURL, Pins: true},
			{Flag: "input", Kind: targetInput},
			{Flag: "input-file", Kind: targetFile},
			{Flag: "raw-request-file", Kind: targetFile},
		},
		ReachFlags: []reachFlag{{Flag: "all", Reach: reachUnbounded}},
		Note:       "the positional is a search over stored records; --target overrides the scheme, host and port the request is sent to",
	},
	"traffic": {
		Reach: reachNone,
		Targets: []targetSpec{
			{Flag: "host", Kind: targetHost},
			{Flag: "url", Kind: targetURL},
			{Flag: "uuid", Kind: targetRecordUUID},
			{Flag: "scan-uuid", Kind: targetScanUUID},
		},
		ReachFlags: []reachFlag{
			{Flag: "replay", Reach: reachStore},
			{Flag: "all", With: "replay", Reach: reachUnbounded},
		},
		Note: "a listing sends nothing; --replay re-sends the matched records",
	},
	"finding verify": {
		Reach:   reachStore,
		Targets: []targetSpec{{Positional: positionalEach, Kind: targetFindingID}, {Flag: "scan-uuid", Kind: targetScanUUID}},
	},
	"ingest": {
		Reach: reachNone,
		Targets: []targetSpec{
			{Flag: "input", Kind: targetInput},
			{Flag: "dir", Kind: targetFile},
			{Flag: "target", Kind: targetURL},
			{Flag: "target-file", Kind: targetFile},
		},
		ReachFlags: []reachFlag{
			{Flag: "spec-url", Reach: reachLine},
			{Flag: "fetch-responses", Reach: reachLine},
			{Flag: "scan-on-receive", Reach: reachLine},
			{Flag: "full-native-scan-on-receive", Reach: reachLine},
		},
		Note: "stores request-only inputs as templates and sends nothing unless a reach flag says so",
	},
	"auth check": {
		Reach:   reachLine,
		Targets: []targetSpec{{Positional: positionalFirst, Kind: targetFile}, {Flag: "url", Kind: targetURL}},
		Note:    "the positional is a session file or a stored session name",
	},
	"kit param-mine": {
		Reach:   reachLine,
		Targets: []targetSpec{{Positional: positionalFirst, Kind: targetURL}, {Flag: "target", Kind: targetURL}},
	},
	"kit h2-probe": {
		Reach:   reachLine,
		Targets: []targetSpec{{Positional: positionalFirst, Kind: targetURL}, {Flag: "target", Kind: targetURL}},
	},
	"kit unlock-walk": {
		Reach:   reachLine,
		Targets: []targetSpec{{Flag: "profile", Kind: targetFile}, {Flag: "origin", Kind: targetURL, Pins: true}},
		Note:    "the walk's origin is the profile's; --origin pins it on the line",
	},
	"kit js-beautify": {
		Reach:   reachLine,
		Targets: []targetSpec{{Positional: positionalFirst, Kind: targetInput}},
		Note:    "an http(s) positional is fetched; a path or - is read locally",
	},
	"kit harvest": {
		Reach:   reachNone,
		Targets: []targetSpec{{Positional: positionalEach, Kind: targetHost}},
		Note:    "asks URL archives about the domains; nothing is sent to them",
	},
	"dns": {
		Reach:   reachNone,
		Targets: []targetSpec{{Positional: positionalEach, Kind: targetHost}, {Flag: "target", Kind: targetHost}, {Flag: "target-file", Kind: targetFile}},
		Note:    "queries go to resolvers, not to the names",
	},
	"dig":    {Reach: reachNone, Note: "translates to `dns`; queries go to resolvers"},
	"host":   {Reach: reachNone, Note: "translates to `dns`; queries go to resolvers"},
	"ffuf":   {Reach: reachLine, Note: "translates ffuf's argv to `fuzz` or `run discovery`; explain-argv reports the translated line"},
	"nuclei": {Reach: reachLine, Note: "translates nuclei's argv to `run known-issue-scan`; explain-argv reports the translated line"},
	"katana": {Reach: reachLine, Note: "translates katana's argv to `run spidering`; explain-argv reports the translated line"},
	"gau":    {Reach: reachLine, Note: "translates gau's argv to `run external-harvest`; explain-argv reports the translated line"},
	"arjun":  {Reach: reachLine, Note: "translates arjun's argv to `fuzz --fuzz new-param`; explain-argv reports the translated line"},
	"agent autopilot": {
		Reach:   reachUnbounded,
		Targets: []targetSpec{{Flag: "target", Kind: targetURL}, {Flag: "record-uuid", Kind: targetRecordUUID}, {Flag: "input", Kind: targetInput}},
		Note:    "the agent chooses its own requests from the seed",
	},
	"agent swarm": {
		Reach:   reachUnbounded,
		Targets: []targetSpec{{Flag: "target", Kind: targetURL}, {Flag: "record-uuid", Kind: targetRecordUUID}, {Flag: "input", Kind: targetInput}},
		Note:    "the agents choose their own requests from the seed",
	},
	"agent triage": {
		Reach:      reachStore,
		Targets:    []targetSpec{{Positional: positionalFirst, Kind: targetFindingID}},
		ReachFlags: []reachFlag{{Flag: "no-probe", Reach: reachNone}},
	},
	"agent olium": {Reach: reachUnbounded, Note: "an interactive agent chooses its own requests"},
	"olium":       {Reach: reachUnbounded, Note: "an interactive agent chooses its own requests"},
	"server":      {Reach: reachUnbounded, Note: "scans the traffic it receives"},
	"js": {
		Reach:   reachUnbounded,
		Targets: []targetSpec{{Flag: "target", Kind: targetURL}},
		Note:    "a script's vigolium.http calls reach any URL it names; --target only sets TARGET",
	},
	"extensions run": {
		Reach:      reachNone,
		Targets:    []targetSpec{{Flag: "record-uuid", Kind: targetRecordUUID}},
		ReachFlags: []reachFlag{{Flag: "allow-network", Reach: reachUnbounded}},
		Note:       "offline unless --allow-network",
	},
}

// Reach levels (reachTrait.Reach, reachFlag.Reach).
const (
	reachNone      = "none"
	reachLine      = "line"
	reachStore     = "store"
	reachUnbounded = "unbounded"
)

// Target kinds (targetSpec.Kind).
const (
	targetURL        = "url"
	targetHost       = "host"
	targetFile       = "file"
	targetInput      = "input" // a path, - for stdin, or inline request text naming its destinations
	targetRecordUUID = "record_uuid"
	targetScanUUID   = "scan_uuid"
	targetFindingID  = "finding_id"
)

// Positional target forms (targetSpec.Positional).
const (
	positionalFirst = "first"
	positionalEach  = "each"
)

// Scan pipelines (`schema commands -j` pipeline). A command runs one when its
// flag set carries scanPipelineAnnotation, which the registrar of the
// pipeline's flags sets: registerScanPipelineFlags ("full": scan, run,
// fingerprint) and registerLightweightScanIOFlags ("single-request": scan-url,
// scan-request, which scan the one request they name).
const (
	scanPipelineAnnotation = "vigolium/scan-pipeline"
	pipelineFull           = "full"
	pipelineSingleRequest  = "single-request"
)

// pipelineOf is the scan pipeline c runs, or "" when it runs none.
func pipelineOf(c *cobra.Command) string {
	pipeline := ""
	c.Flags().VisitAll(func(f *pflag.Flag) {
		if v := f.Annotations[scanPipelineAnnotation]; len(v) > 0 {
			pipeline = v[0]
		}
	})
	return pipeline
}

// phaseFrontDoors are the commands that run one phase whatever --only, --skip
// or --strategy the line passes, keyed by path: each pins globalOnly to the
// phase before it runs the scan.
var phaseFrontDoors = map[string]string{"fingerprint": fingerprintPhase}

// translatesTo lists every native command line a command runs as, whatever
// else its argv says: a tool shim's translations, or `run <phase>` for a phase
// front door. Nil for every other command.
func translatesTo(path string) []string {
	if s, ok := shimSpecByName(path); ok {
		return slices.Clone(s.translatesTo)
	}
	if phase, ok := phaseFrontDoors[path]; ok {
		return []string{"run " + phase}
	}
	return nil
}

// globalReachFlags reach none whatever the command: they print and exit.
var globalReachFlags = []reachFlag{
	{Flag: "help", Reach: reachNone},
	{Flag: "usage", Reach: reachNone},
	{Flag: "dry-run", Reach: reachNone},
}

// reachTrait is one command's row of commandReach.
type reachTrait struct {
	Reach      string
	Targets    []targetSpec
	ReachFlags []reachFlag
	Note       string
}

// targetSpec names one argv word that names a target.
type targetSpec struct {
	// Flag is the long name with dashes; Short its shorthand when it has one
	// (filled from the command's flag set).
	Flag  string `json:"flag,omitempty"`
	Short string `json:"short,omitempty"`
	// Positional is "first" (the first positional) or "each" (every
	// positional).
	Positional string `json:"positional,omitempty"`
	// Kind is url, host, file, input, record_uuid, scan_uuid or finding_id.
	Kind string `json:"kind"`
	// Pins: when this flag is set, every request the command sends goes to
	// its destination, and the command's other targets (a request file, a
	// stored record, a profile) only supply the requests' shape. A guard
	// that judges the pinning value has judged every destination.
	Pins bool `json:"pins,omitempty"`
}

// reachFlag is one flag that changes a command's reach when set.
type reachFlag struct {
	Flag string `json:"flag"`
	// Short is the flag's shorthand, when it has one (filled from the
	// command's flag set, as WithShort is for With).
	Short string `json:"short,omitempty"`
	// With names a flag that must also be set for this entry to apply.
	With      string `json:"with,omitempty"`
	WithShort string `json:"with_short,omitempty"`
	Reach     string `json:"reach"`
}

// reachOf is a command's reach row with flag names dashed and shorthands
// filled, as published.
func reachOf(path string, c *cobra.Command) (reach string, targets []targetSpec, flags []reachFlag, note string) {
	t, ok := commandReach[path]
	if !ok {
		return reachNone, []targetSpec{}, []reachFlag{}, ""
	}
	targets = make([]targetSpec, 0, len(t.Targets))
	for _, s := range t.Targets {
		if s.Flag != "" {
			if f := c.Flags().Lookup(s.Flag); f != nil && f.Shorthand != "" {
				s.Short = "-" + f.Shorthand
			}
			s.Flag = "--" + s.Flag
		}
		targets = append(targets, s)
	}
	flags = make([]reachFlag, 0, len(t.ReachFlags))
	for _, f := range t.ReachFlags {
		if pf := c.Flags().Lookup(f.Flag); pf != nil && pf.Shorthand != "" {
			f.Short = "-" + pf.Shorthand
		}
		f.Flag = "--" + f.Flag
		if f.With != "" {
			if pf := c.Flags().Lookup(f.With); pf != nil && pf.Shorthand != "" {
				f.WithShort = "-" + pf.Shorthand
			}
			f.With = "--" + f.With
		}
		flags = append(flags, f)
	}
	return t.Reach, targets, flags, t.Note
}

// commandAliases lists every spelling of c's path other than the canonical
// one: each segment by its name or any of its aliases. `run` adds
// `run <phase>` for every spelling of every phase it accepts.
func commandAliases(c *cobra.Command) []string {
	var segments [][]string
	for p := c; p != nil && p.HasParent(); p = p.Parent() {
		segments = append([][]string{append([]string{p.Name()}, p.Aliases...)}, segments...)
	}
	canonical := commandPathWithoutRoot(c)
	spellings := []string{""}
	for _, names := range segments {
		var next []string
		for _, prefix := range spellings {
			for _, n := range names {
				next = append(next, strings.TrimSpace(prefix+" "+n))
			}
		}
		spellings = next
	}
	out := []string{}
	for _, s := range spellings {
		if s != canonical {
			out = append(out, s)
		}
	}
	if canonical == "run" {
		for _, p := range runner.PhaseVocabulary() {
			if !p.OnlyAccepted {
				continue
			}
			for _, name := range append([]string{p.Canonical}, p.Aliases...) {
				for _, verb := range append([]string{"run"}, c.Aliases...) {
					out = append(out, verb+" "+name)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}
