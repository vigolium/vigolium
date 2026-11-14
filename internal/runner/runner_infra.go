package runner

import (
	"context"
	"fmt"
	"github.com/vigolium/vigolium/pkg/knownissuescan"
	"github.com/vigolium/vigolium/pkg/modules/passive/surface_scoring"
	"github.com/vigolium/vigolium/pkg/spitolas"
	nethttp "net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/notify"
	"github.com/vigolium/vigolium/pkg/notify/discord"
	"github.com/vigolium/vigolium/pkg/notify/telegram"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// buildInfrastructure extracts common setup from the old RunNativeScan into a reusable struct.
//
// ctx is the scan context (already carrying --scanning-max-duration when set),
// threaded in so the one piece of setup that talks to the network — the session
// login flows — is cancellable and bounded like everything else. Nothing else
// here blocks: the rest is in-process construction.
func (r *Runner) buildInfrastructure(ctx context.Context, plan NativeScanPlan) (*phaseInfra, error) {
	// Auto-generate scan UUID when not provided via --scan-uuid
	scanUUID := r.options.ScanUUID
	if scanUUID == "" {
		scanUUID = uuid.New().String()
		r.options.ScanUUID = scanUUID
	}

	infra := &phaseInfra{
		scanUUID: scanUUID,
	}

	// Create notifier with backends. Each backend is gated by the
	// notify.provider selector — empty means "all", a specific value
	// activates only that channel.
	if r.settings != nil && r.settings.Notify.Enabled {
		var backends []notify.Backend
		notifyCfg := &r.settings.Notify

		// Telegram backend (from settings or env). Construction no longer
		// contacts Telegram (see telegram.NewClient), so this cannot delay the
		// first phase; what it can still report is a malformed token or chat id,
		// which used to be dropped on the floor — an operator who enabled
		// notifications and mistyped the config got no notifications and no
		// explanation, matching the Discord branch below.
		if notifyCfg.IsProviderActive(config.NotifyProviderTelegram) {
			tgOpts := r.buildTelegramOptions()
			if tg, err := telegram.NewBackend(tgOpts...); err == nil {
				backends = append(backends, tg)
				zap.L().Info("[Notify] Telegram backend enabled")
			} else {
				zap.L().Warn("[Notify] Failed to create Telegram backend", zap.Error(err))
			}
		}

		// Discord backend (from settings or env)
		if notifyCfg.IsProviderActive(config.NotifyProviderDiscord) {
			webhookURL := notifyCfg.Discord.WebhookURL
			if webhookURL == "" {
				webhookURL = os.Getenv("DISCORD_WEBHOOK_URL")
			}
			if webhookURL != "" {
				if dc, err := discord.NewBackend(webhookURL); err == nil {
					backends = append(backends, dc)
					zap.L().Info("[Notify] Discord backend enabled")
				} else {
					zap.L().Warn("[Notify] Failed to create Discord backend", zap.Error(err))
				}
			}
		}

		if len(backends) > 0 {
			infra.notifier = notify.New(notify.Config{
				Backends:          backends,
				AllowedSeverities: notifyCfg.Severities,
				RedactHeaders:     headerNameSet(r.options.Headers),
				NoRedact:          r.settings.Output.RedactEvidence != nil && !*r.settings.Output.RedactEvidence,
			})
		}
	}

	// Create runtime services
	svc := &services.Services{
		Options:      r.options,
		Notifier:     infra.notifier,
		DedupManager: r.dedupManager,
		RateLimiter:  buildScanRateLimiter(effectiveRateLimit(r.options)),
	}

	if cache := newHostErrorCache(r.options, r.settings, r.currentPhaseName); cache != nil {
		svc.HostErrors = cache
	}

	// Create HostLimiter for per-host concurrency control
	maxPerHost := r.options.MaxPerHost
	if !r.options.MaxPerHostExplicitlySet {
		// Not chosen on the CLI: let newHostLimiter apply the common
		// scanning_pace value, then its own floor.
		maxPerHost = 0
	}
	hostLimiter := newHostLimiter(maxPerHost, r.settings, r.options.NoWafPacing)
	svc.HostLimiter = hostLimiter
	infra.hostLimiter = hostLimiter
	// The scan's one egress gate over the three components above: every target
	// sender (requester, discovery, login, port-sweep) admits through it or a
	// view of it, so they share one wire-attempt counter.
	// The request budget (armRequestBudget) rides on the root gate, so every
	// view taken from it — phase-local paces included — is held to it.
	svc.Egress = egress.New(egress.Config{Rate: svc.RateLimiter, Hosts: hostLimiter, Breaker: svc.HostErrors}).
		WithBudget(r.requestBudget)
	infra.svc = svc

	// Create scope matcher from settings, passing CLI targets for cli_origin_mode
	// filtering. Built before the requester so the in-scope redirect mode (the
	// default) can judge every hop against it from the first request (SAFE-2).
	if r.settings != nil {
		infra.scopeMatcher = config.NewScopeMatcher(r.settings.Scope, r.scopeTargets()...)
		svc.HopScope = infra.scopeMatcher.HostInScope
		// The traffic policy is resolved once, here, before any sender exists
		// (SAFE-8); every sender reads it from the shared options.
		if r.options.TrafficPolicy == nil {
			r.options.TrafficPolicy = types.NewTrafficPolicy(r.settings.Scope.Methods)
		}
	}
	// --offline (SAFE-11): nothing leaves for a non-target network path.
	if r.offline() {
		r.applyOffline()
	}

	httpRequester, err := http.NewRequester(r.options, svc)
	if err != nil {
		infra.Close()
		return nil, errors.Wrap(err, "could not create http requester")
	}
	infra.httpRequester = httpRequester

	// Phases that never contact the target are unaffected by session headers and
	// request hooks, so neither is built for them. See SendsTargetTraffic for why
	// this is not merely about setup cost.
	reachesTarget := plan.SendsTargetTraffic()

	// OAST registration starts before the extension engine is built, so
	// extensions get the scan's service (vigolium.oast.*): it used to start
	// last, and the engine was built with no service at all.
	r.startOASTRegistration(plan, infra)

	// Initialize JS extension engine
	if reachesTarget && r.settings != nil && r.settings.DynamicAssessment.Extensions.Enabled {
		jsEngine, err := jsext.NewEngine(&r.settings.DynamicAssessment.Extensions, httpRequester, r.jsEngineOptions(infra))
		if err != nil {
			zap.L().Warn("Failed to initialize JS extensions", zap.Error(err))
		} else if loadErr := r.reportExtensionFailures(jsEngine); loadErr != nil {
			// An extension named with --ext did not load: stop here, before the
			// session login below sends the first request.
			infra.Close()
			return nil, loadErr
		} else {
			// Create hook chain if hooks are defined
			preHooks := jsEngine.PreHooks()
			postHooks := jsEngine.PostHooks()
			if len(preHooks) > 0 || len(postHooks) > 0 {
				infra.hookChain = jsext.NewHookChain(preHooks, postHooks)
				zap.L().Info("JS hooks loaded",
					zap.Int("pre_hooks", len(preHooks)),
					zap.Int("post_hooks", len(postHooks)))
			}
			// Store the engine in infra for module resolution
			infra.jsEngine = jsEngine
		}
	}

	// A module selection naming an ext- ID no extension carries is a usage
	// error; fail here, after the engine loaded and before the session login
	// below sends the first request.
	if err := r.validateExtensionSelection(plan, infra.jsEngine); err != nil {
		infra.Close()
		return nil, err
	}

	// Initialize multi-session support for IDOR/BOLA testing. Skipped when no
	// enabled phase will reach the target: see reachesTarget above.
	if reachesTarget {
		if err := r.initSessions(ctx, infra); err != nil {
			// If the user explicitly configured sessions, surface the error clearly
			hasCLIAuth := len(r.options.AuthFiles) > 0 || len(r.options.AuthInline) > 0
			if hasCLIAuth && !r.options.AuthBestEffort {
				return nil, fmt.Errorf("session initialization failed: %w", err)
			}
			// Continuing unauthenticated. Recorded so the assessment phases can
			// say so instead of letting a wall of 401s read as an open app.
			infra.authFailureReason = authFailureReason(ctx, err)
			zap.L().Warn("Failed to initialize sessions, continuing without session support", zap.Error(err))
		}
	}

	return infra, nil
}

// jsEngineOptions builds the extension engine's options for this scan: its
// scan and project, the store, the scope matcher built for the scan, and the
// OAST service when one was started.
func (r *Runner) jsEngineOptions(infra *phaseInfra) *jsext.EngineOptions {
	opts := &jsext.EngineOptions{
		ScanUUID:    r.options.ScanUUID,
		ProjectUUID: r.options.ProjectUUID,
		Repository:  r.repository,
		LLMClient:   extensionLLMClient(r.settings),
		OASTService: infra.oast,
	}
	if r.settings != nil {
		scopeCfg := r.settings.Scope
		opts.ScopeConfig = &scopeCfg
		// The same matcher, from the same settings and the same targets, as
		// the one built above - so share it rather than paying for a second.
		opts.ScopeMatcher = infra.scopeMatcher
	}
	return opts
}

// oastReadyWait bounds how long dynamic assessment waits, at its start, for an
// OAST registration that has not finished yet. Registration starts while the
// infrastructure is built, so on any scan with a discovery or spidering phase it
// has long finished by then; this only matters for a slow server on a scan that
// goes straight to assessment.
const oastReadyWait = 3 * time.Second

// startOASTRegistration begins interactsh registration in the background when
// OAST is enabled and dynamic assessment is in the plan, so the earlier phases
// hide its latency. It never blocks; the outcome is collected by awaitOAST.
func (r *Runner) startOASTRegistration(plan NativeScanPlan, infra *phaseInfra) {
	if infra.oast != nil || r.settings == nil || !r.settings.OAST.Enabled || !planRunsDynamicAssessment(plan) {
		return
	}
	infra.oast = r.newOASTService(infra)
}

// planRunsDynamicAssessment reports whether the dynamic-assessment step is
// enabled in plan.
func planRunsDynamicAssessment(plan NativeScanPlan) bool {
	for _, step := range plan.Steps {
		if step.Phase == PhaseDynamicAssessment {
			return step.Enabled
		}
	}
	return false
}

// newOASTService constructs the scan's OAST service; registration with an
// interactsh server proceeds in the background (see oast.New).
func (r *Runner) newOASTService(infra *phaseInfra) *oast.Service {
	onOASTResult := func(result *output.ResultEvent) {
		if r.output == nil {
			return
		}
		if err := r.output.Write(result); err != nil {
			zap.L().Error("Failed to write OAST result", zap.Error(err))
		}
	}
	cfg := r.settings.OAST
	// A stateless scan's store is discarded with the run: a session kept in
	// it could never be polled, and its keys would only sit in a temp file.
	if r.options.Stateless {
		cfg.KeepSession = false
	}
	svc, err := oast.New(&cfg, onOASTResult, r.repository, infra.scanUUID, r.options.ProjectUUID, nil)
	if err != nil {
		zap.L().Debug("OAST: service construction failed", zap.Error(err))
		return nil
	}
	return svc
}

// awaitOAST resolves the scan's OAST service at the start of dynamic
// assessment. It waits at most oastReadyWait for a registration still in flight.
// When OAST is ready it returns the service for the executors; otherwise it
// closes it, reports the gap once (phase reason oast_unavailable, an
// oast.unavailable event and one stderr line) and returns nil, and the phase
// runs without out-of-band checks. A registration that would have finished later
// is abandoned on purpose: the scan has already said OAST was unavailable, and
// planting payloads halfway through the phase would contradict it.
func (r *Runner) awaitOAST(ctx context.Context, infra *phaseInfra) *oast.Service {
	if r.settings == nil || !r.settings.OAST.Enabled {
		return nil
	}
	if infra.oast == nil {
		// Not started with the infrastructure (a caller that built phaseInfra
		// some other way): start now and give it the same bounded wait.
		infra.oast = r.newOASTService(infra)
		if infra.oast == nil {
			return nil
		}
	}
	svc := infra.oast
	err := svc.WaitReady(ctx, oastReadyWait)
	if err == nil {
		return svc
	}
	svc.Close()
	infra.oast = nil
	if ctx.Err() != nil {
		// The phase is being torn down anyway; its own reason says why.
		return nil
	}
	r.reportOASTUnavailable(err)
	return nil
}

// reportOASTUnavailable is the single operator-facing notice that out-of-band
// checks were skipped: a non-stopping phase reason, an oast.unavailable event,
// and one stderr line.
func (r *Runner) reportOASTUnavailable(err error) {
	r.currentPhase.Load().markPartial(database.ReasonOASTUnavailable)
	scanevents.Emit(scanevents.Event{
		Type:    scanevents.TypeOASTUnavailable,
		Phase:   string(PhaseDynamicAssessment),
		Message: err.Error(),
		Detail:  "blind/out-of-band checks skipped",
	})
	msg := fmt.Sprintf("OAST unavailable (%s) — blind/out-of-band checks skipped", err.Error())
	r.scanLogger.Warn("dynamic-assessment", msg)
	zap.L().Debug("OAST unavailable", zap.Error(err))
	r.printPhaseDetail(fmt.Sprintf("%s %s", terminal.Yellow(terminal.SymbolWarning), msg))
}

// runDiscoveryPhase ingests all input into the database without running modules.
// It combines the original input source with deparos content discovery (if enabled),
// expanding deparos targets with hosts discovered by prior phases (ExternalHarvest, Spidering).
// phaseDeadline derives a phase-scoped context bounded by maxDuration so a phase
// cannot run past its configured scanning_pace max_duration. It is the single
// chokepoint for the "wrap the WHOLE phase, not just one leg" invariant that
// known-issue-scan once regressed on (the Nuclei leg was bounded but the
// secret-scan leg ran on the raw ctx). When maxDuration <= 0 the phase is
// unbounded: the parent ctx is returned unchanged with a no-op cancel so callers
// can always `defer cancel()`. When the parent already has an earlier deadline
// (e.g. the overall scan budget), context.WithTimeout keeps that earlier
// deadline, so a phase can never extend the scan.
func phaseDeadline(ctx context.Context, maxDuration time.Duration) (context.Context, context.CancelFunc) {
	return phaseDeadlineReserved(ctx, maxDuration, 0)
}

// phaseDeadlineReserved is phaseDeadline that also keeps reserveAfter (0..1)
// of the time the parent context has left for the phases that come after this
// one (ECON-5): when ctx carries the scan's total budget, the phase's deadline
// is capped at (1 - reserveAfter) of what remains. Without a parent deadline,
// or with reserveAfter 0, it is phaseDeadline.
func phaseDeadlineReserved(ctx context.Context, maxDuration time.Duration, reserveAfter float64) (context.Context, context.CancelFunc) {
	if reserveAfter > 0 && reserveAfter < 1 {
		if dl, ok := ctx.Deadline(); ok {
			if limit := time.Duration(float64(time.Until(dl)) * (1 - reserveAfter)); limit > 0 && (maxDuration <= 0 || limit < maxDuration) {
				maxDuration = limit
			}
		}
	}
	if maxDuration <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, maxDuration)
}

// newScanRecordWriter returns a batched record writer for one phase of this
// scan. Every row it inserts is stamped with the scan's UUID; a row it dedups
// onto keeps the scan that stored it first (see RecordWriterConfig.ScanUUID).
// Every runner phase builds its writer here, so http_records.scan_uuid is set on
// all of them — the browser crawl writes through it without knowing about scans.
//
// r.options.ScanUUID, not a phaseInfra field: buildInfrastructure writes the
// minted UUID back into the options before any phase runs, and the re-spider
// helpers that need a writer are not handed the infra.
func (r *Runner) newScanRecordWriter() *database.RecordWriter {
	return database.NewRecordWriter(r.repository, database.RecordWriterConfig{
		ScanUUID: r.options.ScanUUID,
		// Score each record's attack surface at ingest so the assessment's
		// (risk, surface) order means something on a fresh scan (ECON-5).
		SurfaceScorer: surface_scoring.IngestScore,
	})
}

// offline reports whether this run is --offline (flag or settings key).
func (r *Runner) offline() bool {
	return r.options.Offline || (r.settings != nil && r.settings.Offline)
}

// applyOffline turns off every non-target network path for the run
// (SAFE-11): OAST registration, third-party lookups (externalFetcher returns
// nil), nuclei template clones and browser downloads.
func (r *Runner) applyOffline() {
	r.options.Offline = true
	if r.settings != nil {
		r.settings.OAST.Enabled = false
		r.settings.DynamicAssessment.ExternalLookups = false
	}
	spitolas.SetOffline(true)
	knownissuescan.SetOffline(true)
}

// externalFetcher is the client modules use for third-party lookups that are
// not the target (SAFE-11), built from the scan's proxy and timeout. nil
// unless dynamic_assessment.external_lookups is on and the run is not offline.
func (r *Runner) externalFetcher() *nethttp.Client {
	if r.offline() || r.settings == nil || !r.settings.DynamicAssessment.ExternalLookups {
		return nil
	}
	transport := &nethttp.Transport{Proxy: nethttp.ProxyFromEnvironment}
	if r.options.ProxyURL != "" {
		if u, err := url.Parse(r.options.ProxyURL); err == nil {
			transport.Proxy = nethttp.ProxyURL(u)
		}
	}
	timeout := r.options.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &nethttp.Client{Timeout: timeout, Transport: transport}
}

// headerNameSet is the lowercased name set of "Name: value" header strings.
func headerNameSet(headers []string) map[string]struct{} {
	out := make(map[string]struct{}, len(headers))
	for _, h := range headers {
		if name, _, ok := strings.Cut(h, ":"); ok {
			if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
				out[n] = struct{}{}
			}
		}
	}
	return out
}
