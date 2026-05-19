package recon

import (
	"fmt"
	"sort"
	"strings"
)

// Render produces a compact markdown block describing the report,
// intended for direct inclusion in the plan agent's prompt under a
// `## Reconnaissance Findings` heading (the caller adds the heading).
//
// The output is deliberately short: only sections with actual signal
// are emitted, evidence lines are deduplicated, and long lists are
// capped. Goal is < ~50 lines for typical targets.
func Render(r *TechStackReport) string {
	if r == nil || !r.HasSignal() {
		return ""
	}
	var sb strings.Builder

	if len(r.Stacks) > 0 {
		sb.WriteString("**Detected stack:**\n")
		// Order: high → medium → low confidence; stable within each tier.
		ordered := make([]StackDetection, len(r.Stacks))
		copy(ordered, r.Stacks)
		sort.SliceStable(ordered, func(i, j int) bool {
			return ordered[i].Confidence > ordered[j].Confidence
		})
		for _, s := range ordered {
			line := fmt.Sprintf("- %s", s.Name)
			if s.Version != "" {
				line += " " + s.Version
			}
			if s.Tag != "" {
				line += fmt.Sprintf(" [tag: `%s`]", s.Tag)
			}
			if s.Confidence != 0 {
				line += fmt.Sprintf(" (%s confidence)", s.Confidence)
			}
			sb.WriteString(line)
			sb.WriteByte('\n')
			for _, ev := range dedupStrings(s.Evidence, 3) {
				sb.WriteString("  - ")
				sb.WriteString(ev)
				sb.WriteByte('\n')
			}
		}
		sb.WriteByte('\n')
	}

	if len(r.APISpecs) > 0 {
		sb.WriteString("**API surface:**\n")
		for _, spec := range r.APISpecs {
			note := ""
			if spec.Note != "" {
				note = " — " + spec.Note
			}
			sb.WriteString(fmt.Sprintf("- %s spec at %s (HTTP %d)%s\n", spec.Kind, spec.URL, spec.StatusCode, note))
		}
		sb.WriteByte('\n')
	}

	if len(r.SensitivePaths) > 0 {
		sb.WriteString("**Sensitive paths reachable:**\n")
		for _, p := range r.SensitivePaths {
			sb.WriteString(fmt.Sprintf("- %s (HTTP %d) — %s\n", p.Path, p.StatusCode, p.Reason))
		}
		sb.WriteByte('\n')
	}

	if r.CORS != nil && (r.CORS.Permissive || r.CORS.Reflective) {
		sb.WriteString("**CORS posture:**\n")
		flag := "reflective"
		if r.CORS.Permissive {
			flag = "permissive (Access-Control-Allow-Origin: *)"
		}
		sb.WriteString(fmt.Sprintf("- %s with Access-Control-Allow-Credentials: %q\n",
			flag, defaultIfEmpty(r.CORS.AllowCredentials, "(absent)")))
		if r.CORS.AllowMethods != "" {
			sb.WriteString(fmt.Sprintf("- Access-Control-Allow-Methods: %s\n", r.CORS.AllowMethods))
		}
		sb.WriteByte('\n')
	}

	if len(r.SecurityHeaders.Missing) > 0 {
		sb.WriteString("**Missing security headers:** ")
		sb.WriteString(strings.Join(r.SecurityHeaders.Missing, ", "))
		sb.WriteString("\n\n")
	}

	if len(r.AllowedMethods) > 0 {
		sb.WriteString("**OPTIONS-reported allowed methods:**\n")
		paths := make([]string, 0, len(r.AllowedMethods))
		for p := range r.AllowedMethods {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			sb.WriteString(fmt.Sprintf("- %s → %s\n", p, strings.Join(r.AllowedMethods[p], ", ")))
		}
		sb.WriteByte('\n')
	}

	if len(r.WellKnown) > 0 {
		sb.WriteString("**Well-known paths reachable:**\n")
		// Cap to first 8 to keep prompt lean.
		limit := len(r.WellKnown)
		if limit > 8 {
			limit = 8
		}
		for i := 0; i < limit; i++ {
			w := r.WellKnown[i]
			sb.WriteString(fmt.Sprintf("- %s (HTTP %d)\n", w.Path, w.StatusCode))
		}
		if len(r.WellKnown) > limit {
			sb.WriteString(fmt.Sprintf("- … and %d more\n", len(r.WellKnown)-limit))
		}
		sb.WriteByte('\n')
	}

	if len(r.JSSignals) > 0 {
		sb.WriteString("**Client-side stack signals (JS):**\n")
		for _, j := range r.JSSignals {
			line := "- " + j.Name
			if j.Tag != "" {
				line += fmt.Sprintf(" [tag: `%s`]", j.Tag)
			}
			if j.Evidence != "" {
				line += " — " + j.Evidence
			}
			sb.WriteString(line + "\n")
		}
		sb.WriteByte('\n')
	}

	if r.FaviconHash != "" {
		sb.WriteString(fmt.Sprintf("**Favicon MD5:** `%s` (cross-reference with public favicon-hash databases for fingerprinting)\n\n", r.FaviconHash))
	}

	if len(r.VHostFindings) > 0 {
		sb.WriteString("**Virtual-host anomalies:**\n")
		for _, v := range r.VHostFindings {
			sb.WriteString("- " + v.Reason + "\n")
		}
		sb.WriteByte('\n')
	}

	if len(r.MethodMatrix) > 0 {
		sb.WriteString("**Methods accepted (PUT/DELETE/PATCH, beyond OPTIONS Allow):**\n")
		paths := make([]string, 0, len(r.MethodMatrix))
		for p := range r.MethodMatrix {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			sb.WriteString(fmt.Sprintf("- %s → %s (possible broken access control — these methods usually 405 on read-only endpoints)\n", p, strings.Join(r.MethodMatrix[p], ", ")))
		}
		sb.WriteByte('\n')
	}

	if len(r.LoginCandidates) > 0 {
		sb.WriteString("**Login forms detected:**\n")
		for _, lc := range r.LoginCandidates {
			fields := ""
			if lc.UsernameName != "" || lc.PasswordName != "" {
				fields = fmt.Sprintf(" (fields: %s / %s)", defaultIfEmpty(lc.UsernameName, "?"), defaultIfEmpty(lc.PasswordName, "?"))
			}
			act := ""
			if lc.Action != "" {
				act = " → " + lc.Action
			}
			sb.WriteString(fmt.Sprintf("- %s%s%s\n", lc.URL, fields, act))
		}
		sb.WriteString("(Authenticated scanning is recommended — pass `--browser-auth`, `--cookie`, or `--header 'Authorization: …'` to the swarm CLI.)\n\n")
	}

	// Module-tag hint — directly actionable for the planner.
	if tags := r.ModuleTagSuggestions(); len(tags) > 0 {
		sb.WriteString("**Suggested MODULE_TAGS to focus the scan:** `")
		sb.WriteString(strings.Join(tags, "`, `"))
		sb.WriteString("`\n")
	}

	return strings.TrimRight(sb.String(), "\n")
}

// RenderConsoleSummary produces a single-line summary suitable for the
// recon phase's console output. Caller wraps it in terminal styling.
func RenderConsoleSummary(r *TechStackReport) string {
	if r == nil {
		return "no signal"
	}
	parts := make([]string, 0, 4)
	if len(r.Stacks) > 0 {
		names := make([]string, 0, len(r.Stacks))
		for _, s := range r.Stacks {
			if len(names) >= 4 {
				names = append(names, fmt.Sprintf("+%d more", len(r.Stacks)-len(names)))
				break
			}
			label := s.Name
			if s.Version != "" {
				label += " " + s.Version
			}
			names = append(names, label)
		}
		parts = append(parts, "stacks: "+strings.Join(names, ", "))
	}
	if len(r.APISpecs) > 0 {
		parts = append(parts, fmt.Sprintf("%d API spec(s)", len(r.APISpecs)))
	}
	if len(r.SensitivePaths) > 0 {
		parts = append(parts, fmt.Sprintf("%d sensitive path(s)", len(r.SensitivePaths)))
	}
	if r.CORS != nil && (r.CORS.Permissive || r.CORS.Reflective) {
		parts = append(parts, "CORS concern")
	}
	if len(r.SecurityHeaders.Missing) > 0 {
		parts = append(parts, fmt.Sprintf("%d missing security headers", len(r.SecurityHeaders.Missing)))
	}
	if len(r.JSSignals) > 0 {
		parts = append(parts, fmt.Sprintf("%d JS framework signal(s)", len(r.JSSignals)))
	}
	if len(r.VHostFindings) > 0 {
		parts = append(parts, fmt.Sprintf("%d vhost anomaly(ies)", len(r.VHostFindings)))
	}
	if len(r.LoginCandidates) > 0 {
		parts = append(parts, "login form detected")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d probes, no signal", r.ProbeCount)
	}
	return fmt.Sprintf("%d probes — %s", r.ProbeCount, strings.Join(parts, "; "))
}

func dedupStrings(in []string, max int) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if len(out) >= max {
			break
		}
	}
	return out
}

func defaultIfEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
