package database

import (
	"fmt"
	"sort"
	"strings"
)

// Caveat is one statement about what a scan did NOT cover, derived from its
// phase outcomes and module errors: a blocked host, a phase cut short, findings
// a cap dropped, modules that failed. It is the end-of-scan coverage statement
// rendered under the finished banner, on the -j scan document (`caveats`) and
// on scan.finished (`caveats`). Derived, never stored: the outcomes it reads
// are the persisted record.
type Caveat struct {
	Code    string   `json:"code"`
	Phase   string   `json:"phase,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
	Modules []string `json:"modules,omitempty"`
	Count   int64    `json:"count,omitempty"`
	Message string   `json:"message"`
}

// CaveatModuleErrors is the caveat code for modules that errored during the
// scan (not a phase reason: a module failure does not make a phase partial).
const CaveatModuleErrors = "module_errors"

// caveatMessages phrase the codes a reader most needs explained. Codes absent
// here are rendered generically.
var caveatMessages = map[string]string{
	ReasonEdgeBlocked:        "a WAF/CDN edge blocked requests; results for these hosts may be incomplete",
	ReasonPhaseDeadline:      "the phase hit its time limit before covering all its input",
	ReasonScanBudget:         "the total scan time budget ran out",
	ReasonRequestBudget:      "the request budget (--max-requests) ran out",
	ReasonCancelled:          "the scan was interrupted",
	ReasonUserStopped:        "the scan was stopped on request before it finished",
	ReasonTargetsUnreachable: "some targets did not answer",
	ReasonTargetsFailed:      "some targets errored",
	ReasonTargetsSkipped:     "some targets were never attempted",
	ReasonFeedbackDropped:    "discovered endpoints were dropped from the feedback queue and not tested",
	ReasonAuthUnavailable:    "configured authentication could not be applied; the phase ran unauthenticated",
	ReasonAuthUnverified:     "a session's login could not be verified",
	ReasonAuthLost:           "the session expired mid-scan and re-login did not restore it",
	ReasonBrowserUnavailable: "the crawl browser failed to launch",
	ReasonOASTUnavailable:    "out-of-band checks did not run",
	ReasonInputIncomplete:    "the phase stopped before its input was exhausted",
	LimitFindingsPerModule:   "findings past --max-findings-per-module were not reported",
	LimitHostRequestBudget:   "hosts used their whole --max-requests-per-host",
	CaveatModuleErrors:       "modules errored; their checks may be incomplete",
}

// CoverageCaveats turns a scan's outcome into the caveats a reader should see
// next to its findings, in phase order then code order. moduleErrors is the
// per-module error tally (scans.module_errors). Phases skipped for having
// nothing to do contribute nothing (PhaseOutcome.BenignSkip).
func CoverageCaveats(c ScanCompletion, moduleErrors map[string]int64) []Caveat {
	var out []Caveat
	for _, p := range c.Phases {
		if p.BenignSkip() {
			continue
		}
		for _, reason := range p.Reasons {
			cv := Caveat{Code: reason, Phase: p.Phase}
			switch reason {
			case ReasonEdgeBlocked:
				cv.Hosts = p.BlockedHosts
			case ReasonTargetsUnreachable, ReasonNoTargetsReachable:
				if p.Targets != nil {
					for _, issue := range p.Targets.Unreachable {
						cv.Hosts = append(cv.Hosts, issue.Target)
					}
				}
			case ReasonFeedbackDropped:
				cv.Count = p.Counts[ReasonFeedbackDropped]
			}
			cv.Message = caveatMessage(reason)
			out = append(out, cv)
		}
		for _, note := range p.Notes {
			out = append(out, Caveat{Code: note, Phase: p.Phase, Message: caveatMessage(note)})
		}
		if len(p.FindingsCapped) > 0 {
			cv := Caveat{Code: LimitFindingsPerModule, Phase: p.Phase, Message: caveatMessage(LimitFindingsPerModule)}
			cv.Modules, cv.Count = rankModules(p.FindingsCapped)
			out = append(out, cv)
		}
		if len(p.BudgetExhaustedHosts) > 0 {
			out = append(out, Caveat{Code: LimitHostRequestBudget, Phase: p.Phase, Hosts: p.BudgetExhaustedHosts,
				Message: caveatMessage(LimitHostRequestBudget)})
		}
	}
	if len(moduleErrors) > 0 {
		cv := Caveat{Code: CaveatModuleErrors, Message: caveatMessage(CaveatModuleErrors)}
		cv.Modules, cv.Count = rankModules(moduleErrors)
		out = append(out, cv)
	}
	return out
}

func caveatMessage(code string) string {
	if m, ok := caveatMessages[code]; ok {
		return m
	}
	return strings.ReplaceAll(code, "_", " ")
}

// rankModules returns module ids by count (highest first, then id) and the
// total.
func rankModules(counts map[string]int64) ([]string, int64) {
	ids := make([]string, 0, len(counts))
	var total int64
	for id, n := range counts {
		ids = append(ids, id)
		total += n
	}
	sort.Slice(ids, func(i, j int) bool {
		if counts[ids[i]] != counts[ids[j]] {
			return counts[ids[i]] > counts[ids[j]]
		}
		return ids[i] < ids[j]
	})
	return ids, total
}

// Line renders the caveat as one human line (no color), naming at most five
// hosts or modules.
func (c Caveat) Line() string {
	var b strings.Builder
	if c.Phase != "" {
		b.WriteString(c.Phase)
		b.WriteString(": ")
	}
	b.WriteString(c.Message)
	if c.Count > 0 && c.Code != CaveatModuleErrors && c.Code != LimitFindingsPerModule {
		fmt.Fprintf(&b, " (%d)", c.Count)
	}
	names := c.Hosts
	if len(names) == 0 {
		names = c.Modules
	}
	if len(names) > 0 {
		shown := names
		if len(shown) > 5 {
			shown = shown[:5]
		}
		b.WriteString(" — ")
		b.WriteString(strings.Join(shown, ", "))
		if len(names) > len(shown) {
			fmt.Fprintf(&b, ", +%d more", len(names)-len(shown))
		}
		if c.Count > 0 && (c.Code == CaveatModuleErrors || c.Code == LimitFindingsPerModule) {
			fmt.Fprintf(&b, " (%d total)", c.Count)
		}
	}
	b.WriteString(" [")
	b.WriteString(c.Code)
	b.WriteString("]")
	return b.String()
}

// ScopeDroppedCountPrefix prefixes the PhaseOutcome.Counts keys that count the
// records a scope rule class refused ("scope_dropped.status_code").
const ScopeDroppedCountPrefix = "scope_dropped."

// ScopeDropped sums the per-class scope drops across a scan's phases; nil when
// scope dropped nothing.
func ScopeDropped(phases []PhaseOutcome) map[string]int64 {
	var out map[string]int64
	for _, p := range phases {
		for k, n := range p.Counts {
			class, ok := strings.CutPrefix(k, ScopeDroppedCountPrefix)
			if !ok || n <= 0 {
				continue
			}
			if out == nil {
				out = map[string]int64{}
			}
			out[class] += n
		}
	}
	return out
}
