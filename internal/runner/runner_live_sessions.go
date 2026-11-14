package runner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// CountResponsesWhileLoggedOut is the PhaseOutcome.Counts key for the
// responses a phase received while a session was logged out (the work behind
// them ran unauthenticated). Set alongside the responses_while_logged_out
// limit.
const CountResponsesWhileLoggedOut = database.LimitResponsesWhileLoggedOut

// liveSessions is the scan's in-flight authentication: one LiveSession per
// session that has a `check` block or an expiring credential (each holds the
// Manager it re-logs in through). Built by initSessions, closed by
// phaseInfra.Close. A nil *liveSessions is a scan with no live session; every
// method is nil-safe.
type liveSessions struct {
	// primary is the primary session's live owner, nil when it has no check.
	primary *authentication.LiveSession
	// assessment is primary when only the assessment phases carry it
	// (session.use_in_discovery: false); nil otherwise.
	assessment *authentication.LiveSession
	all        []*authentication.LiveSession
}

func (l *liveSessions) close() {
	if l == nil {
		return
	}
	for _, s := range l.all {
		s.Close()
	}
}

func (l *liveSessions) primaryLive() *authentication.LiveSession {
	if l == nil {
		return nil
	}
	return l.primary
}

func (l *liveSessions) assessmentLive() *authentication.LiveSession {
	if l == nil {
		return nil
	}
	return l.assessment
}

// trackPhase accounts the phase's share of every live session's logged-out
// traffic on t when the phase finishes: the responses_while_logged_out limit
// plus its count, and auth_lost when a session that this phase sent traffic
// with is failed.
func (l *liveSessions) trackPhase(t *phaseTracker) {
	if l == nil || len(l.all) == 0 || t == nil {
		return
	}
	type baseline struct {
		s         *authentication.LiveSession
		out, seen int64
	}
	bases := make([]baseline, len(l.all))
	for i, s := range l.all {
		bases[i] = baseline{s: s, out: s.LoggedOutResponses(), seen: s.Observed()}
	}
	t.onFinish(func(t *phaseTracker) {
		var lost int64
		for _, b := range bases {
			lost += b.s.LoggedOutResponses() - b.out
			if b.s.State() == authentication.LiveFailed && b.s.Observed() > b.seen {
				t.markPartial(database.ReasonAuthLost)
			}
		}
		if lost > 0 {
			t.noteLimit(database.LimitResponsesWhileLoggedOut)
			t.setCount(CountResponsesWhileLoggedOut, lost)
		}
	})
}

// newLiveSession wraps a hydrated session that has a check block, or whose
// login reported when its credentials expire (an OAuth2 token, refreshed
// shortly before expires_at). pinned are the header names the operator set
// with -H, which the session never overrides. A session whose check cannot be
// armed (a relative check.url with nothing to resolve it against) is logged
// and scanned with frozen credentials, as before.
func (r *Runner) newLiveSession(ctx context.Context, mgr *authentication.Manager, sess *authentication.Session, pinned []string) *authentication.LiveSession {
	if sess == nil || (sess.Check == nil && sess.ExpiresAt().IsZero()) {
		return nil
	}
	base := ""
	if len(r.options.Targets) > 0 {
		base = r.options.Targets[0]
	}
	live, err := authentication.NewLiveSession(sess, authentication.LiveOptions{
		Manager:   mgr,
		ProbeBase: base,
		Pinned:    pinned,
		OnEvent:   r.onLiveSessionEvent,
		Context:   ctx,
	})
	if err != nil {
		zap.L().Warn("Session check not armed; its credentials will not be refreshed mid-scan",
			zap.String("session", sess.Name), zap.Error(err))
		return nil
	}
	return live
}

// onLiveSessionEvent turns a LiveSession's report into the scan's own:
// auth.session_suspect / auth.relogin events, and on a lost session the
// running phase's auth_lost reason and, under reauth.on_failure: abort, the
// scan's cancellation with an *AuthLostError.
func (r *Runner) onLiveSessionEvent(ev authentication.LiveEvent) {
	tracker := r.currentPhase.Load()
	phase := ""
	if tracker != nil {
		phase = tracker.phase
	}
	switch ev.Kind {
	case authentication.LiveEventSuspect:
		scanevents.Emit(scanevents.Event{
			Type:    scanevents.TypeAuthSessionSuspect,
			Phase:   phase,
			Session: ev.Session,
			Gen:     ev.Gen,
			Detail:  ev.Reason,
		})
	case authentication.LiveEventRelogin:
		ok := ev.OK
		e := scanevents.Event{
			Type:    scanevents.TypeAuthRelogin,
			Phase:   phase,
			Session: ev.Session,
			Gen:     ev.Gen,
			OK:      &ok,
			Count:   scanevents.Int64(int64(ev.Attempts)),
		}
		if ev.Err != nil {
			e.Message = ev.Err.Error()
		}
		scanevents.Emit(e)
		if ok {
			r.printPhaseDetail(fmt.Sprintf("session %s expired and was logged in again (credential generation %d)",
				terminal.HiBlue(ev.Session), ev.Gen))
			// Browser crawls re-apply the new credentials.
			r.relogins.notify()
		}
	case authentication.LiveEventLost:
		tracker.markPartial(database.ReasonAuthLost)
		cause := "re-login failed"
		if ev.Err != nil {
			cause = ev.Err.Error()
		}
		if ev.OnFailure == authentication.ReauthAbort {
			r.printPhaseDetail(fmt.Sprintf("%s session %s is logged out and %s — stopping the scan (reauth.on_failure: abort)",
				terminal.Yellow(terminal.SymbolWarning), ev.Session, cause))
			if abort := r.authAbort.Load(); abort != nil {
				(*abort)(&AuthLostError{Session: ev.Session, Err: ev.Err})
			}
			return
		}
		r.printPhaseDetail(fmt.Sprintf("%s session %s is logged out and %s — the scan continues unauthenticated (auth_lost)",
			terminal.Yellow(terminal.SymbolWarning), ev.Session, cause))
	}
}

// AuthLostError ends a scan whose session expired, could not be logged in
// again, and was configured with reauth.on_failure: abort. error.code is
// login_failed.
type AuthLostError struct {
	Session string
	Err     error
}

func (e *AuthLostError) Error() string {
	msg := fmt.Sprintf("session %q is logged out and re-login did not restore it (reauth.on_failure: abort)", e.Session)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *AuthLostError) Unwrap() error { return e.Err }

// Code is the machine error code (see pkg/apicontract).
func (e *AuthLostError) Code() apicontract.ErrorCode { return apicontract.CodeLoginFailed }

// armAuthAbort derives the context the phases run under so a session lost
// under reauth.on_failure: abort can cancel it with an *AuthLostError as the
// cause. The returned stop releases it.
func (r *Runner) armAuthAbort(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	r.authAbort.Store(&cancel)
	return ctx, func() {
		r.authAbort.Store(nil)
		cancel(nil)
	}
}

// authLostCause is the *AuthLostError that cancelled ctx, or nil.
func authLostCause(ctx context.Context) *AuthLostError {
	if ctx == nil || ctx.Err() == nil {
		return nil
	}
	var e *AuthLostError
	if errors.As(context.Cause(ctx), &e) {
		return e
	}
	return nil
}

// headerNames is the lowercased set of names in "Name: value" headers.
func headerNames(headers []string) []string {
	var out []string
	for _, h := range headers {
		if name, _, ok := strings.Cut(h, ":"); ok {
			if n := strings.TrimSpace(name); n != "" {
				out = append(out, strings.ToLower(n))
			}
		}
	}
	return out
}

// withoutHeaders drops the "Name: value" entries whose name is in names
// (lowercased), so a session header never shadows the operator's -H.
func withoutHeaders(headers, names []string) []string {
	if len(names) == 0 {
		return headers
	}
	var out []string
	for _, h := range headers {
		name, _, _ := strings.Cut(h, ":")
		drop := false
		for _, n := range names {
			if strings.EqualFold(strings.TrimSpace(name), n) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, h)
		}
	}
	return out
}

// overlayCredentials replaces, in headers, every header the live credentials
// carry with its current value: the snapshot a phase that cannot use the
// requester (nuclei) takes at its start gets the latest generation.
func overlayCredentials(headers []string, creds *authentication.Credentials) []string {
	if creds == nil || len(creds.Headers) == 0 {
		return headers
	}
	owned := make([]string, 0, len(creds.Headers))
	for name := range creds.Headers {
		owned = append(owned, strings.ToLower(name))
	}
	out := withoutHeaders(headers, owned)
	for name, value := range creds.Headers {
		out = append(out, name+": "+value)
	}
	return out
}
