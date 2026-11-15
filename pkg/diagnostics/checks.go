package diagnostics

import (
	"sort"
	"strings"
)

// CheckStatusUnverified is a check whose configuration is complete but whose
// live dependency was not contacted (an agent provider behind an endpoint):
// `doctor --for agent` probes it.
const CheckStatusUnverified = "unverified"

// Check is one flat row of a report: what `doctor -j` lists as items and what
// `--only` selects. The nested Report stays the server's /diagnostics shape;
// this is a view over it.
type Check struct {
	ID string `json:"id"`
	// Group is the section the check belongs to: core, native_scan, agent,
	// audit, tools or coding_agent.
	Group string `json:"group"`
	// Status is ok, warning, error, unverified or skipped.
	Status  string   `json:"status"`
	Message string   `json:"message,omitempty"`
	Affects []string `json:"affects,omitempty"`
	FixArgv []string `json:"fix_argv,omitempty"`
	Tip     string   `json:"tip,omitempty"`
	Details []string `json:"details,omitempty"`
	// Source names the setting the check tested and the layer that set it
	// ("oast.server_url from env:VIGOLIUM_OAST_DOMAIN"), on a failing check.
	Source string `json:"source,omitempty"`
}

// checkMeta is what a check id affects when it fails and how to fix it.
var checkMeta = map[string]struct {
	group   string
	affects []string
	fix     string // --only key for `doctor --fix`
}{
	"config":           {group: "core", affects: []string{"every setting falls back to defaults"}},
	"scope":            {group: "core", affects: []string{"requests the broken rule touches"}},
	"database":         {group: "core", affects: []string{"storing records and findings (every stateful command)"}},
	"initialized":      {group: "core"},
	"proxy":            {group: "core", affects: []string{"every request"}},
	"chromium":         {group: "native_scan", affects: []string{"spidering (browser crawl)", "DOM XSS confirmation"}, fix: "chrome"},
	"nuclei_templates": {group: "native_scan", affects: []string{"known-issue scan (nuclei)"}, fix: "nuclei"},
	"jstangle":         {group: "native_scan", affects: []string{"JavaScript endpoint extraction in discovery"}},
	"oast":             {group: "native_scan", affects: []string{"blind (out-of-band) checks"}},
	"agent":            {group: "agent", affects: []string{"every agent mode"}},
	"sessions_dir":     {group: "agent", affects: []string{"agent session persistence"}},
	"templates_dir":    {group: "agent", affects: []string{"agent prompt templates"}},
	"browser":          {group: "agent", affects: []string{"agent browser tool"}, fix: "agent-browser"},
	"audit":            {group: "audit", affects: []string{"agent audit"}},
	"vigolium-audit":   {group: "audit", affects: []string{"agent audit (Path A)"}, fix: "vigolium-audit"},
	"piolium":          {group: "audit", affects: []string{"agent audit --driver piolium (Path B)"}, fix: "piolium"},
	"queue":            {group: "core", affects: []string{"server scan queue"}},
	"skill":            {group: "coding_agent", affects: []string{"the coding-agent skill is stale"}, fix: "skill"},
	"bun":              {group: "tools", fix: "bun"},
	"claude":           {group: "tools", affects: []string{"agent audit (Path A)"}, fix: "claude"},
	"agent-browser":    {group: "tools", affects: []string{"agent browser tool"}, fix: "agent-browser"},
	"pi":               {group: "tools", affects: []string{"agent audit (Path B)"}, fix: "pi"},
}

// Checks flattens the report into one row per check, in report order: core,
// native scan, agent, audit, tools, coding agent.
func (r *Report) Checks() []Check {
	if r == nil {
		return nil
	}
	var out []Check
	addResult := func(id string, c *CheckResult) {
		if c != nil {
			out = append(out, newCheck(id, string(c.Status), c.Message, c.Tip, c.Details))
		}
	}
	addTool := func(id string) {
		if t := r.Tools[id]; t != nil {
			msg := t.Message
			if t.Status == StatusOK && t.Path != "" {
				msg = t.Path
			}
			out = append(out, newCheck(id, string(t.Status), msg, t.Tip, t.Details))
		}
	}
	addResult("config", r.Config)
	addResult("scope", r.Scope)
	addResult("database", r.Database)
	addResult("initialized", r.Initialized)
	addTool("chromium")
	addResult("nuclei_templates", r.NucleiTemplates)
	if r.EmbeddedBinaries != nil {
		addResult("jstangle", r.EmbeddedBinaries["jstangle"])
	}
	addResult("oast", r.OAST)
	if a := r.Agent; a != nil {
		status := string(a.Status)
		if a.Status == StatusOK && a.Unverified {
			status = CheckStatusUnverified
		}
		msg := a.Message
		if msg == "" {
			msg = a.Protocol
		}
		out = append(out, newCheck("agent", status, msg, a.Tip, a.Details))
	}
	addResult("sessions_dir", r.SessionsDir)
	addResult("templates_dir", r.TemplatesDir)
	addResult("browser", r.Browser)
	addResult("audit", r.Audit)
	if r.EmbeddedBinaries != nil {
		addResult("vigolium-audit", r.EmbeddedBinaries["vigolium-audit"])
	}
	addResult("piolium", r.Piolium)
	addResult("queue", r.Queue)
	// Tools, in a stable order: the fixable ones first, then the rest.
	seen := map[string]bool{"chromium": true}
	for _, id := range []string{"bun", "claude", "agent-browser", "pi"} {
		addTool(id)
		seen[id] = true
	}
	var rest []string
	for id := range r.Tools {
		if !seen[id] {
			rest = append(rest, id)
		}
	}
	sort.Strings(rest)
	for _, id := range rest {
		addTool(id)
	}
	addResult("skill", r.Skill)
	return out
}

func newCheck(id, status, message, tip string, details []string) Check {
	c := Check{ID: id, Status: status, Message: message, Tip: tip, Details: details}
	meta, ok := checkMeta[id]
	if !ok {
		meta.group = "tools"
	}
	c.Group = meta.group
	if status != string(StatusOK) {
		c.Affects = meta.affects
		if meta.fix != "" {
			c.FixArgv = []string{"vigolium", "doctor", "--fix", "--only", meta.fix}
		}
	}
	return c
}

// CheckIDForToken maps a `doctor --only` token (a check id, or a --fix key or
// alias such as chrome, nuclei, nuclei-templates) to its check id, or "".
func CheckIDForToken(token string, checks []Check) string {
	t := strings.ToLower(strings.TrimSpace(token))
	switch ResolveFixKey(t) {
	case "chromium":
		return "chromium"
	case "nuclei-templates":
		return "nuclei_templates"
	}
	for _, c := range checks {
		if c.ID == t || strings.ReplaceAll(c.ID, "_", "-") == t {
			return c.ID
		}
	}
	return ""
}

// Capability states.
const (
	CapabilityAvailable   = "available"
	CapabilityUnavailable = "unavailable"
	CapabilityUnverified  = "unverified"
)

// Capabilities says what still works, so a degraded verdict names its cost.
type Capabilities struct {
	Scan           string `json:"scan"`
	Spidering      string `json:"spidering"`
	KnownIssueScan string `json:"known_issue_scan"`
	OutOfBand      string `json:"out_of_band"`
	Agent          string `json:"agent"`
	Audit          string `json:"audit"`
}

// Capabilities derives what works from the report.
func (r *Report) Capabilities() Capabilities {
	avail := func(ok bool) string {
		if ok {
			return CapabilityAvailable
		}
		return CapabilityUnavailable
	}
	resultOK := func(c *CheckResult) bool { return c != nil && c.Status == StatusOK }
	if r == nil {
		r = &Report{}
	}
	caps := Capabilities{
		Scan:           avail(resultOK(r.Database)),
		Spidering:      avail(r.Tools["chromium"] != nil && r.Tools["chromium"].Status == StatusOK),
		KnownIssueScan: avail(resultOK(r.NucleiTemplates)),
		OutOfBand:      avail(resultOK(r.OAST)),
		Agent:          avail(r.Agent != nil && r.Agent.Status == StatusOK),
		Audit:          avail(AuditPathA(r).OK || AuditPathB(r).OK),
	}
	if r.Agent != nil && r.Agent.Status == StatusOK && r.Agent.Unverified {
		caps.Agent = CapabilityUnverified
	}
	return caps
}
