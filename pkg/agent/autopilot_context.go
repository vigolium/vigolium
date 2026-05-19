package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/archon"
)

type AutopilotContextBundle struct {
	Version         string                    `json:"version"`
	Mode            string                    `json:"mode"`
	TargetURL       string                    `json:"target,omitempty"`
	SourcePath      string                    `json:"source_path,omitempty"`
	DiffRef         string                    `json:"diff_ref,omitempty"`
	ChangedFiles    []string                  `json:"changed_files,omitempty"`
	Routes          []AutopilotRouteSummary   `json:"routes,omitempty"`
	AuthFlows       []AutopilotAuthFlow       `json:"auth_flows,omitempty"`
	Findings        []AutopilotFindingSummary `json:"findings,omitempty"`
	Priorities      []string                  `json:"priorities,omitempty"`
	ArchonAvailable bool                      `json:"archon_available"`
	ArchonStatus    string                    `json:"archon_status,omitempty"`
	PreparedAuth    *AutopilotPreparedAuth    `json:"prepared_auth,omitempty"`
	BrowserDecision string                    `json:"browser_decision,omitempty"`
	BrowserReason   string                    `json:"browser_reason,omitempty"`
	Warnings        []string                  `json:"warnings,omitempty"`
}

type AutopilotRouteSummary struct {
	Path   string `json:"path"`
	Method string `json:"method,omitempty"`
	Source string `json:"source,omitempty"`
}

type AutopilotAuthFlow struct {
	Name      string   `json:"name"`
	LoginPath string   `json:"login_path,omitempty"`
	Tokens    []string `json:"tokens,omitempty"`
}

type AutopilotFindingSummary struct {
	ID         string   `json:"id,omitempty"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Action     string   `json:"action,omitempty"`
	Kind       string   `json:"kind,omitempty"`
	Route      string   `json:"route,omitempty"`
	Locations  []string `json:"locations,omitempty"`
}

type AutopilotExecutionPlan struct {
	AuthRequired   bool                  `json:"auth_required"`
	AuthPrepared   bool                  `json:"auth_prepared,omitempty"`
	BrowserMode    string                `json:"browser_mode,omitempty"`
	BrowserReason  string                `json:"browser_reason,omitempty"`
	Budgets        map[string]int        `json:"budgets,omitempty"`
	Tasks          []AutopilotPlanTask   `json:"tasks,omitempty"`
	StopCriteria   []string              `json:"stop_criteria,omitempty"`
	Warnings       []string              `json:"warnings,omitempty"`
	ArtifactPolicy AutopilotArtifactSpec `json:"artifact_policy"`
}

type AutopilotPlanTask struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Priority int    `json:"priority"`
	Reason   string `json:"reason"`
}

type AutopilotPreparedAuth struct {
	Requested       bool     `json:"requested"`
	Source          string   `json:"source,omitempty"`
	SessionConfig   string   `json:"session_config_path,omitempty"`
	SessionCount    int      `json:"session_count,omitempty"`
	Hydrated        bool     `json:"hydrated"`
	HeaderCount     int      `json:"header_count,omitempty"`
	AuthRequired    bool     `json:"auth_required"`
	RequiresBrowser bool     `json:"requires_browser,omitempty"`
	BrowserStartURL string   `json:"browser_start_url,omitempty"`
	FocusRoutes     []string `json:"focus_routes,omitempty"`
	ProtectedRoutes []string `json:"protected_routes,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

type AutopilotArtifactSpec struct {
	BriefPath            string `json:"brief_path"`
	ContextPath          string `json:"context_path"`
	PlanPath             string `json:"plan_path"`
	FindingsPath         string `json:"findings_path"`
	DismissedPath        string `json:"dismissed_path"`
	VisitedEndpointsPath string `json:"visited_endpoints_path"`
	ArtifactsPath        string `json:"artifacts_path"`
	SessionConfigPath    string `json:"session_config_path"`
	AuthStatePath        string `json:"auth_state_path"`
	AuthHeadersPath      string `json:"auth_headers_path"`
	BrowserSessionPath   string `json:"browser_session_path"`
	EvidenceDir          string `json:"evidence_dir"`
	VerificationPath     string `json:"verification_path"`
}

type AutopilotVerificationReport struct {
	ConfirmedCount int      `json:"confirmed_count"`
	DismissedCount int      `json:"dismissed_count"`
	Warnings       []string `json:"warnings,omitempty"`
}

func buildAutopilotContextBundle(cfg AutopilotPipelineConfig, ac *archonContext, archonStatus string, warnings []string) AutopilotContextBundle {
	mode := "target-only"
	switch {
	case cfg.TargetURL != "" && cfg.SourcePath != "":
		mode = "target+source"
	case cfg.TargetURL == "" && cfg.SourcePath != "":
		mode = "source-only"
	}

	bundle := AutopilotContextBundle{
		Version:         "autopilot",
		Mode:            mode,
		TargetURL:       cfg.TargetURL,
		SourcePath:      cfg.SourcePath,
		ArchonAvailable: ac != nil,
		ArchonStatus:    archonStatus,
		Warnings:        append([]string(nil), warnings...),
	}

	if cfg.DiffContext != nil {
		bundle.DiffRef = cfg.DiffContext.DiffRef
		bundle.ChangedFiles = append(bundle.ChangedFiles, cfg.DiffContext.ChangedFiles...)
	}

	if ac != nil {
		bundle.Findings = summarizeArchonFindings(ac.Findings)
		bundle.Routes = inferRoutesFromArchon(ac.Findings)
		bundle.AuthFlows = inferAuthFlows(ac.Findings)
	}
	if cfg.PreparedAuth != nil {
		copyAuth := *cfg.PreparedAuth
		copyAuth.FocusRoutes = append([]string(nil), cfg.PreparedAuth.FocusRoutes...)
		copyAuth.ProtectedRoutes = append([]string(nil), cfg.PreparedAuth.ProtectedRoutes...)
		copyAuth.Notes = append([]string(nil), cfg.PreparedAuth.Notes...)
		bundle.PreparedAuth = &copyAuth
	}

	bundle.Priorities = buildAutopilotPriorities(cfg, bundle)
	modeDecision, modeReason := decideBrowserUsage(cfg, bundle)
	bundle.BrowserDecision = modeDecision
	bundle.BrowserReason = modeReason
	return bundle
}

func buildAutopilotPlan(cfg AutopilotPipelineConfig, bundle AutopilotContextBundle, spec AutopilotArtifactSpec) AutopilotExecutionPlan {
	budgets := buildAutopilotBudgets(cfg.MaxCommands)
	plan := AutopilotExecutionPlan{
		AuthRequired:   cfg.AuthRequired || len(bundle.AuthFlows) > 0 || strings.Contains(strings.ToLower(cfg.Focus), "auth"),
		AuthPrepared:   cfg.PreparedAuth != nil && cfg.PreparedAuth.Hydrated,
		BrowserMode:    bundle.BrowserDecision,
		BrowserReason:  bundle.BrowserReason,
		Budgets:        budgets,
		StopCriteria:   buildStopCriteria(cfg, bundle),
		ArtifactPolicy: spec,
	}

	priority := 1
	if plan.AuthRequired {
		plan.Tasks = append(plan.Tasks, AutopilotPlanTask{
			ID:       "t1",
			Type:     "auth",
			Priority: priority,
			Reason:   firstNonEmpty(bundle.BrowserReason, "protected or login-gated routes detected"),
		})
		priority++
	}

	if len(bundle.Findings) > 0 {
		plan.Tasks = append(plan.Tasks, AutopilotPlanTask{
			ID:       fmt.Sprintf("t%d", priority),
			Type:     "validate",
			Priority: priority,
			Reason:   "validate high-confidence findings from prepared whitebox context",
		})
		priority++
	}

	if len(bundle.ChangedFiles) > 0 {
		plan.Tasks = append(plan.Tasks, AutopilotPlanTask{
			ID:       fmt.Sprintf("t%d", priority),
			Type:     "diff-review",
			Priority: priority,
			Reason:   "cover changed-code paths before broad discovery",
		})
		priority++
	}

	plan.Tasks = append(plan.Tasks, AutopilotPlanTask{
		ID:       fmt.Sprintf("t%d", priority),
		Type:     "discover",
		Priority: priority,
		Reason:   "fill remaining attack-surface gaps after priority validation",
	})

	if bundle.BrowserDecision == "browser_required" || bundle.BrowserDecision == "browser_recommended" {
		plan.Warnings = append(plan.Warnings, "persist browser-derived auth artifacts before scanning protected routes")
	}

	return plan
}

func decideBrowserUsage(cfg AutopilotPipelineConfig, bundle AutopilotContextBundle) (string, string) {
	if cfg.RequiresBrowser {
		if !cfg.BrowserEnabled {
			return "browser_unavailable", "browser was explicitly required but tooling is disabled"
		}
		return "browser_required", firstNonEmpty(cfg.BrowserStartURL, "browser was explicitly required for auth setup")
	}
	if cfg.BrowserRequested {
		if !cfg.BrowserEnabled {
			return "browser_unavailable", "browser was explicitly requested but tooling is disabled"
		}
		return "browser_recommended", firstNonEmpty(cfg.BrowserStartURL, "browser was explicitly requested for this run")
	}
	if !cfg.BrowserEnabled {
		return "browser_unavailable", "browser tooling is disabled for this run"
	}

	lowerFocus := strings.ToLower(cfg.Focus)
	authSignals := len(bundle.AuthFlows) > 0
	spaSignals := strings.Contains(lowerFocus, "spa") || strings.Contains(lowerFocus, "oauth") || strings.Contains(lowerFocus, "sso")
	webTarget := strings.HasPrefix(strings.ToLower(cfg.TargetURL), "http")

	switch {
	case spaSignals || authSignals && webTarget:
		return "browser_recommended", "login or browser-managed session flows are likely relevant"
	case webTarget && len(bundle.Findings) > 0 && containsProtectedHint(bundle.Findings):
		return "browser_recommended", "findings suggest authenticated browser flows may be needed"
	default:
		return "browser_unneeded", "direct HTTP probing should be attempted first"
	}
}

func buildAutopilotBudgets(maxCommands int) map[string]int {
	if maxCommands <= 0 {
		maxCommands = 100
	}
	auth := maxCommands / 10
	if auth < 5 {
		auth = 5
	}
	recon := maxCommands / 5
	if recon < 8 {
		recon = 8
	}
	validate := maxCommands / 2
	if validate < 12 {
		validate = 12
	}
	extension := maxCommands / 10
	if extension < 5 {
		extension = 5
	}
	report := maxCommands - auth - recon - validate - extension
	if report < 5 {
		report = 5
	}

	return map[string]int{
		"auth":      auth,
		"recon":     recon,
		"validate":  validate,
		"extension": extension,
		"report":    report,
	}
}

func buildStopCriteria(cfg AutopilotPipelineConfig, bundle AutopilotContextBundle) []string {
	criteria := []string{
		"All exploit-priority findings have been attempted or disproved",
		"Every confirmed finding includes reproducible evidence",
		"No new high-value endpoints are discovered in the latest recon pass",
	}
	if len(bundle.ChangedFiles) > 0 {
		criteria = append(criteria, "Changed-code paths have been covered before broad discovery")
	}
	if len(bundle.AuthFlows) > 0 {
		criteria = append(criteria, "Authentication has been established or explicitly ruled out")
	}
	if cfg.PreparedAuth != nil && cfg.PreparedAuth.Hydrated {
		criteria = append(criteria, "Prepared authenticated headers have been exercised against protected routes")
	}
	if cfg.TargetURL == "" {
		criteria = append(criteria, "No dynamic testing is attempted in source-only mode")
	}
	return criteria
}

func summarizeArchonFindings(findings []*archon.ArchonFinding) []AutopilotFindingSummary {
	out := make([]AutopilotFindingSummary, 0, len(findings))
	for i, f := range findings {
		summary := AutopilotFindingSummary{
			ID:         f.FindingID,
			Title:      strings.TrimSpace(firstNonEmpty(f.Title, fmt.Sprintf("finding-%d", i+1))),
			Severity:   f.Severity,
			Confidence: f.Confidence,
			Kind:       inferFindingKind(firstNonEmpty(f.Title, f.Body)),
			Action:     inferFindingAction(f),
			Locations:  compactStrings(f.Locations),
		}
		if route := inferRouteFromFinding(f); route != "" {
			summary.Route = route
		}
		out = append(out, summary)
	}
	return out
}

func inferRoutesFromArchon(findings []*archon.ArchonFinding) []AutopilotRouteSummary {
	seen := map[string]struct{}{}
	var routes []AutopilotRouteSummary
	for _, f := range findings {
		route := inferRouteFromFinding(f)
		if route == "" {
			continue
		}
		key := "GET " + route
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		routes = append(routes, AutopilotRouteSummary{
			Path:   route,
			Method: "",
			Source: "archon",
		})
	}
	return routes
}

func inferAuthFlows(findings []*archon.ArchonFinding) []AutopilotAuthFlow {
	seen := map[string]struct{}{}
	var flows []AutopilotAuthFlow
	for _, f := range findings {
		text := strings.ToLower(firstNonEmpty(f.Title, f.Body))
		if !strings.Contains(text, "auth") && !strings.Contains(text, "login") && !strings.Contains(text, "token") && !strings.Contains(text, "session") {
			continue
		}
		loginPath := inferRouteFromFinding(f)
		name := "application auth flow"
		if strings.Contains(text, "jwt") || strings.Contains(text, "token") {
			name = "jwt login"
		} else if strings.Contains(text, "session") || strings.Contains(text, "cookie") {
			name = "cookie/session login"
		}
		key := name + "|" + loginPath
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		flow := AutopilotAuthFlow{Name: name, LoginPath: loginPath}
		if strings.Contains(text, "token") || strings.Contains(text, "jwt") {
			flow.Tokens = []string{"access_token"}
		}
		flows = append(flows, flow)
	}
	return flows
}

func buildAutopilotPriorities(cfg AutopilotPipelineConfig, bundle AutopilotContextBundle) []string {
	priorities := []string{}
	if len(bundle.ChangedFiles) > 0 {
		priorities = append(priorities, "Validate changed-code paths before broad discovery")
	}
	if len(bundle.Findings) > 0 {
		priorities = append(priorities, "Exploit or disprove high-confidence frozen Archon findings first")
	}
	if len(bundle.AuthFlows) > 0 {
		priorities = append(priorities, "Establish or rule out authentication before scanning protected routes")
	}
	if cfg.PreparedAuth != nil && cfg.PreparedAuth.Hydrated {
		priorities = append(priorities, "Use prepared authenticated state before attempting manual login discovery")
	}
	if len(cfg.FocusRoutes) > 0 {
		priorities = append(priorities, "Prioritize user-requested protected flows: "+strings.Join(cfg.FocusRoutes, ", "))
	}
	if cfg.TargetURL != "" {
		priorities = append(priorities, "Use targeted HTTP scanning before writing custom extensions")
	}
	if len(priorities) == 0 {
		priorities = append(priorities, "Map the attack surface, validate hypotheses, then stop when evidence quality is sufficient")
	}
	return priorities
}

func prepareAutopilotArtifacts(sessionDir string) (AutopilotArtifactSpec, error) {
	spec := AutopilotArtifactSpec{}
	if sessionDir == "" {
		return spec, nil
	}
	archonDir := filepath.Join(sessionDir, "archon")
	autopilotDir := filepath.Join(sessionDir, "autopilot")
	evidenceDir := filepath.Join(autopilotDir, "evidence")
	for _, dir := range []string{
		filepath.Join(archonDir, "raw"),
		filepath.Join(archonDir, "findings"),
		autopilotDir,
		evidenceDir,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return spec, err
		}
	}

	spec = AutopilotArtifactSpec{
		BriefPath:            filepath.Join(autopilotDir, "brief.md"),
		ContextPath:          filepath.Join(autopilotDir, "context.json"),
		PlanPath:             filepath.Join(autopilotDir, "plan.json"),
		FindingsPath:         filepath.Join(autopilotDir, "findings.json"),
		DismissedPath:        filepath.Join(autopilotDir, "dismissed.json"),
		VisitedEndpointsPath: filepath.Join(autopilotDir, "visited-endpoints.json"),
		ArtifactsPath:        filepath.Join(autopilotDir, "artifacts.json"),
		SessionConfigPath:    filepath.Join(autopilotDir, "session-config.json"),
		AuthStatePath:        filepath.Join(autopilotDir, "auth-state.json"),
		AuthHeadersPath:      filepath.Join(autopilotDir, "auth-headers.json"),
		BrowserSessionPath:   filepath.Join(autopilotDir, "browser-session.json"),
		EvidenceDir:          evidenceDir,
		VerificationPath:     filepath.Join(autopilotDir, "verification.json"),
	}
	return spec, nil
}

func writeJSONArtifact(path string, v any) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func writeAutopilotArtifacts(spec AutopilotArtifactSpec, bundle AutopilotContextBundle, plan AutopilotExecutionPlan, brief string) error {
	if spec.BriefPath == "" {
		return nil
	}
	if err := os.WriteFile(spec.BriefPath, []byte(brief), 0o644); err != nil {
		return err
	}
	if err := writeJSONArtifact(spec.ContextPath, bundle); err != nil {
		return err
	}
	if err := writeJSONArtifact(spec.PlanPath, plan); err != nil {
		return err
	}
	manifest := map[string]string{
		"brief":             spec.BriefPath,
		"context":           spec.ContextPath,
		"plan":              spec.PlanPath,
		"findings":          spec.FindingsPath,
		"dismissed":         spec.DismissedPath,
		"visited_endpoints": spec.VisitedEndpointsPath,
		"session_config":    spec.SessionConfigPath,
		"auth_state":        spec.AuthStatePath,
		"auth_headers":      spec.AuthHeadersPath,
		"browser_session":   spec.BrowserSessionPath,
		"verification":      spec.VerificationPath,
	}
	return writeJSONArtifact(spec.ArtifactsPath, manifest)
}

func verifyAutopilotArtifacts(spec AutopilotArtifactSpec) AutopilotVerificationReport {
	report := AutopilotVerificationReport{}
	confirmed, confirmedWarn := countEvidenceBackedFindings(spec.FindingsPath, spec.EvidenceDir)
	report.ConfirmedCount = confirmed
	if confirmedWarn != "" {
		report.Warnings = append(report.Warnings, confirmedWarn)
	}
	dismissed, dismissedWarn := countEvidenceBackedFindings(spec.DismissedPath, "")
	report.DismissedCount = dismissed
	if dismissedWarn != "" {
		report.Warnings = append(report.Warnings, dismissedWarn)
	}
	_ = writeJSONArtifact(spec.VerificationPath, report)
	return report
}

func countEvidenceBackedFindings(path string, evidenceDir string) (int, string) {
	if path == "" {
		return 0, ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Sprintf("artifact missing: %s", filepath.Base(path))
		}
		return 0, fmt.Sprintf("failed to read %s: %v", filepath.Base(path), err)
	}

	var arr []map[string]any
	if err := json.Unmarshal(data, &arr); err != nil {
		var wrapper struct {
			Findings []map[string]any `json:"findings"`
		}
		if err2 := json.Unmarshal(data, &wrapper); err2 != nil {
			return 0, fmt.Sprintf("failed to parse %s as findings artifact", filepath.Base(path))
		}
		arr = wrapper.Findings
	}

	count := 0
	for _, item := range arr {
		if evidenceDir == "" {
			count++
			continue
		}
		if hasEvidence(item, evidenceDir) {
			count++
		}
	}
	if len(arr) > count {
		return count, fmt.Sprintf("%s contains %d entries without evidence references", filepath.Base(path), len(arr)-count)
	}
	return count, ""
}

func hasEvidence(item map[string]any, evidenceDir string) bool {
	for _, key := range []string{"evidence", "evidence_path", "request", "response"} {
		if v, ok := item[key]; ok && strings.TrimSpace(fmt.Sprint(v)) != "" {
			return true
		}
	}
	if raw, ok := item["evidence_files"]; ok {
		switch files := raw.(type) {
		case []any:
			for _, f := range files {
				if strings.TrimSpace(fmt.Sprint(f)) != "" {
					return true
				}
			}
		}
	}
	entries, err := os.ReadDir(evidenceDir)
	return err == nil && len(entries) > 0
}

func inferFindingAction(f *archon.ArchonFinding) string {
	switch strings.ToLower(f.Severity) {
	case "critical", "high":
		return "exploit"
	case "medium":
		return "investigate"
	default:
		return "ignore"
	}
}

func inferFindingKind(text string) string {
	lower := strings.ToLower(text)
	for _, kind := range []string{"auth", "idor", "xss", "sqli", "ssti", "ssrf", "csrf", "cors", "rce", "lfi", "xxe"} {
		if strings.Contains(lower, kind) {
			return kind
		}
	}
	return ""
}

func inferRouteFromFinding(f *archon.ArchonFinding) string {
	for _, loc := range compactStrings(f.Locations) {
		if idx := strings.Index(loc, "/"); idx >= 0 {
			return loc[idx:]
		}
	}
	text := firstNonEmpty(f.Body, f.Title)
	for _, part := range strings.Fields(text) {
		if strings.HasPrefix(part, "/") {
			return strings.TrimRight(part, ".,)")
		}
	}
	return ""
}

func containsProtectedHint(findings []AutopilotFindingSummary) bool {
	for _, f := range findings {
		text := strings.ToLower(f.Title + " " + f.Route + " " + strings.Join(f.Locations, " "))
		if strings.Contains(text, "auth") || strings.Contains(text, "admin") || strings.Contains(text, "login") {
			return true
		}
	}
	return false
}

func compactStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func writePreparedAuthArtifacts(spec AutopilotArtifactSpec, bundle AutopilotContextBundle, plan AutopilotExecutionPlan, prepared *AutopilotPreparedAuth, headers map[string]string, sessionCfg *AgentSessionConfig) {
	state := map[string]any{
		"browser_mode":   plan.BrowserMode,
		"browser_reason": plan.BrowserReason,
		"auth_required":  plan.AuthRequired,
		"auth_prepared":  plan.AuthPrepared,
	}
	if prepared != nil {
		state["prepared_auth"] = prepared
	}
	if bundle.BrowserDecision == "browser_required" || bundle.BrowserDecision == "browser_recommended" {
		state["next_step"] = "Persist browser-derived cookies/tokens before scanning protected routes"
	}
	_ = writeJSONArtifact(spec.AuthStatePath, state)
	_ = writeJSONArtifact(spec.AuthHeadersPath, headers)
	browserState := map[string]any{
		"status": "pending",
		"note":   "populate this artifact when browser-derived session state is captured",
	}
	if prepared != nil {
		browserState["requires_browser"] = prepared.RequiresBrowser
		browserState["browser_start_url"] = prepared.BrowserStartURL
		browserState["focus_routes"] = prepared.FocusRoutes
	}
	_ = writeJSONArtifact(spec.BrowserSessionPath, browserState)
	if sessionCfg != nil && spec.SessionConfigPath != "" {
		_ = writeJSONArtifact(spec.SessionConfigPath, sessionCfg)
	}
}
