package browsercookie

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/browserutils/kooky"
)

func TestClassifyReadErrorSeparatesKeyringFromEverythingElse(t *testing.T) {
	// This is the whole reason the package reports a Problem: the upstream
	// reader folds a keyring failure into a per-row decryption error, so
	// without this classification a denied approval reaches the caller as
	// "that domain has no cookies".
	cases := []struct {
		err  error
		want Problem
	}{
		{errors.New("keyring password retrieval failed: exit status 44"), ProblemKeyringDenied},
		{errors.New("unsupported v20 App-Bound Encryption (requires elevated COM access)"), ProblemEncryptionUnsupported},
		{errors.New("decryption failed"), ProblemDecryptFailed},
		{errors.New("chrome: cipher input not full blocks"), ProblemDecryptFailed},
		{errors.New("invalid last block padding length: 200"), ProblemDecryptFailed},
		{errors.New("open /x/Cookies: permission denied"), ProblemUnreadable},
	}
	for _, c := range cases {
		got, detail := classifyReadError(c.err)
		if got != c.want {
			t.Errorf("classifyReadError(%q) = %q, want %q", c.err, got, c.want)
		}
		if detail == "" {
			t.Errorf("classifyReadError(%q) dropped the detail text", c.err)
		}
	}
}

func TestClassifyReadErrorDegradesToAFailureNotASuccess(t *testing.T) {
	// The classification matches text this package does not own. An upstream
	// rewording must still land on *some* problem — never ProblemNone, which
	// would report a failed read as an empty one.
	got, _ := classifyReadError(errors.New("something nobody has seen before"))
	if got == ProblemNone {
		t.Fatal("an unrecognized read error must still be a problem")
	}
}

func TestResultProblemRanksByWhatTheCallerCanDo(t *testing.T) {
	// A denied keyring is one approval away from working, so it outranks a
	// scheme no retry can fix: that is the message worth surfacing.
	res := Result{Stores: []StoreResult{
		{Problem: ProblemUnreadable, Detail: "unreadable"},
		{Problem: ProblemEncryptionUnsupported, Detail: "app-bound"},
		{Problem: ProblemKeyringDenied, Detail: "denied"},
	}}
	if got := res.Problem(); got != ProblemKeyringDenied {
		t.Errorf("Problem() = %q, want %q", got, ProblemKeyringDenied)
	}
	if got := res.ProblemDetail(); got != "denied" {
		t.Errorf("ProblemDetail() = %q, want the governing problem's detail", got)
	}
}

func TestResultProblemNoneWhenEveryStoreRead(t *testing.T) {
	res := Result{Stores: []StoreResult{{Count: 3}, {Count: 0}}}
	if got := res.Problem(); got != ProblemNone {
		t.Errorf("Problem() = %q, want none", got)
	}
	if got := res.ProblemDetail(); got != "" {
		t.Errorf("ProblemDetail() = %q, want empty", got)
	}
}

func TestCookieSessionAndExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	session := Cookie{Name: "s"}
	if !session.Session() {
		t.Error("a cookie with no expiry is a session cookie")
	}
	// A session cookie has no expiry to compare against, so it must not be
	// filtered out as expired — that would drop the live half of most logins.
	if session.Expired(now) {
		t.Error("a session cookie is not expired by this test")
	}

	past := Cookie{Name: "p", Expires: now.Add(-time.Hour)}
	if !past.Expired(now) {
		t.Error("a past expiry is expired")
	}
	future := Cookie{Name: "f", Expires: now.Add(time.Hour)}
	if future.Expired(now) {
		t.Error("a future expiry is not expired")
	}
}

func TestWarningsForSessionCookiesAndWAL(t *testing.T) {
	res := Result{
		Cookies: []Cookie{{Name: "a"}, {Name: "b", Expires: time.Unix(1_900_000_000, 0)}},
		Stores: []StoreResult{{
			Store: StoreInfo{Browser: "chrome", Profile: "Default", WAL: true},
		}},
	}
	warnings := warningsFor(res, true)
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"SameSite", "unflushed writes", "session cookies"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q:\n%s", want, joined)
		}
	}
}

func TestWarningsForOmitsSameSiteWhenNoSecureCookie(t *testing.T) {
	res := Result{Cookies: []Cookie{{Name: "a", Expires: time.Unix(1_900_000_000, 0)}}}
	for _, w := range warningsFor(res, false) {
		if strings.Contains(w, "SameSite") {
			t.Errorf("unexpected SameSite warning: %q", w)
		}
	}
}

func TestSortCookiesIsStableAcrossRuns(t *testing.T) {
	cookies := []Cookie{
		{Domain: "b.test", Name: "z", Browser: "chrome"},
		{Domain: "a.test", Name: "b", Path: "/z"},
		{Domain: "a.test", Name: "b", Path: "/a"},
		{Domain: "a.test", Name: "a"},
	}
	sortCookies(cookies)
	var got []string
	for _, c := range cookies {
		got = append(got, fmt.Sprintf("%s|%s|%s", c.Domain, c.Name, c.Path))
	}
	want := []string{"a.test|a|", "a.test|b|/a", "a.test|b|/z", "b.test|z|"}
	if !slices.Equal(got, want) {
		t.Errorf("sortCookies produced %v, want %v", got, want)
	}
}

func TestLowerSet(t *testing.T) {
	if got := lowerSet(nil); got != nil {
		t.Errorf("lowerSet(nil) = %v, want nil so callers can skip the filter", got)
	}
	got := lowerSet([]string{"SID", " csrf ", ""})
	if !got["sid"] || !got["csrf"] || len(got) != 2 {
		t.Errorf("lowerSet = %v", got)
	}
}

func TestSameSiteNameMapping(t *testing.T) {
	// Values are http.SameSite's constants; the default case is the one that
	// matters, because the Chromium reader never reports the attribute.
	unset := kookyCookieWithSameSite(0)
	if got := sameSiteName(&unset); got != SameSiteUnknown {
		t.Errorf("unset SameSite = %q, want unknown", got)
	}
	for value, want := range map[int]string{2: "Lax", 3: "Strict", 4: "None"} {
		c := kookyCookieWithSameSite(value)
		if got := sameSiteName(&c); got != want {
			t.Errorf("SameSite(%d) = %q, want %q", value, got, want)
		}
	}
}

// kookyCookieWithSameSite builds an upstream cookie carrying one SameSite
// value, for the mapping test.
func kookyCookieWithSameSite(v int) kooky.Cookie {
	var c kooky.Cookie
	c.SameSite = http.SameSite(v)
	return c
}

func TestKeyringViaDescriptionIsNotEmpty(t *testing.T) {
	via, detail := KeyringViaDescription()
	if via == "" || detail == "" {
		t.Errorf("KeyringViaDescription() = (%q, %q), want both populated", via, detail)
	}
}

func TestPlausibleTimeDropsImpossibleCreationDates(t *testing.T) {
	// The Chromium reader derives creation from the SQLite rowid, which on a
	// live profile produces dates in the year 2185. A caller that sorts or
	// filters on `created` must not be handed one.
	if got := plausibleTime(time.Date(2185, 7, 22, 0, 0, 0, 0, time.UTC)); !got.IsZero() {
		t.Errorf("a far-future creation time should be dropped, got %v", got)
	}
	if got := plausibleTime(time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)); !got.IsZero() {
		t.Errorf("the FILETIME epoch should be dropped, got %v", got)
	}
	if got := plausibleTime(time.Time{}); !got.IsZero() {
		t.Errorf("the zero time stays zero, got %v", got)
	}
	real := time.Now().Add(-24 * time.Hour)
	if got := plausibleTime(real); !got.Equal(real) {
		t.Errorf("a plausible time should pass through, got %v want %v", got, real)
	}
}

// A read blocked on an unanswered keyring prompt is abandoned at the deadline
// and reported as keyring_denied, not left hanging; an interrupt ends it too.
func TestReadStoreBoundedAbandonsABlockedRead(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	prevFn, prevTimeout := readStoreFn, keyringPromptTimeout
	t.Cleanup(func() { readStoreFn, keyringPromptTimeout = prevFn, prevTimeout })
	readStoreFn = func(context.Context, StoreInfo, *Matcher, map[string]bool) ([]Cookie, error) {
		<-release // a security(1) call waiting on a dialog ignores its context
		return nil, nil
	}
	keyringPromptTimeout = 20 * time.Millisecond

	_, err := readStoreBounded(context.Background(), StoreInfo{}, nil, nil)
	if !errors.Is(err, errKeyringTimeout) {
		t.Fatalf("got %v, want errKeyringTimeout", err)
	}
	if p, _ := classifyReadError(err); p != ProblemKeyringDenied {
		t.Errorf("a timed-out prompt classifies as %q, want %q", p, ProblemKeyringDenied)
	}

	keyringPromptTimeout = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	if _, err := readStoreBounded(ctx, StoreInfo{}, nil, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("an interrupt returned %v, want context.Canceled", err)
	}
}
