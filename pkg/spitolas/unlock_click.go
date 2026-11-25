package spitolas

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// The unlock walk's click loop. A rendered admin view often sends its
// interesting calls only when something is clicked: a tab, a search or filter
// submit, the first row's view or edit, an export. On each rendered route the
// walk clicks up to the profile's MaxClicksPerRoute controls.
//
// What admits a click is not this file's trigger matrix:
//
//   - the candidates are the spider's own (action.CandidateElementExtractor),
//     after its destructive-label guard (safety.DestructivePattern: delete,
//     remove, logout, approve, publish, transfer, …, matched on text, href,
//     aria-label, title and value) dropped the controls whose click could act
//     even as a GET;
//   - every request a click sends passes the walk's interceptor like a
//     navigation's: stubs and rewrites apply, a write is failed and reported by
//     shape, nothing off scope is stored;
//   - the walk refuses to click at all when writes are allowed (clickBudget),
//     because a click would then commit a real write.
//
// The trigger matrix only ORDERS the candidates within the cap so that each
// module yields one request shape per action (one search, one filter, the
// first row's view and edit, one export, then tabs and links) rather than
// spending the cap on twenty identical row buttons. It reads labels because
// the walk runs without a model in the loop and must decide per route in
// milliseconds; a misread label only changes which controls fill the cap,
// never whether a control may be clicked.

// unlockClickSettle bounds the network wait after one click; a route's
// settleMs still bounds it when lower.
const unlockClickSettle = 3 * time.Second

// Trigger kinds, in the order the planner takes one of each.
const (
	unlockTriggerSearch = "search"
	unlockTriggerFilter = "filter"
	unlockTriggerView   = "view"
	unlockTriggerEdit   = "edit"
	unlockTriggerExport = "export"
	unlockTriggerList   = "list"
	unlockTriggerOther  = "other"
)

// unlockOnePerKind are the triggers a route clicks at most once: each fires
// the same request shape however many rows carry it.
var unlockOnePerKind = []string{unlockTriggerSearch, unlockTriggerFilter, unlockTriggerView, unlockTriggerEdit, unlockTriggerExport}

// unlockTriggerRes classify a control's label (English and the common CJK
// admin-UI terms), checked in this order: an export label wins over a view
// word beside it, a search over a filter.
var unlockTriggerRes = []struct {
	kind string
	re   *regexp.Regexp
}{
	{unlockTriggerExport, regexp.MustCompile(`(?i)export|download|\bcsv\b|excel|xlsx|导出|下载|匯出|下載`)},
	{unlockTriggerSearch, regexp.MustCompile(`(?i)\bsearch\b|\bquery\b|\bfind\b|\blook ?up\b|搜索|查询|检索|搜尋|查詢`)},
	{unlockTriggerFilter, regexp.MustCompile(`(?i)filter|\bapply\b|\brefine\b|筛选|过滤|篩選`)},
	{unlockTriggerEdit, regexp.MustCompile(`(?i)\bedit\b|\bmodify\b|编辑|修改|編輯`)},
	{unlockTriggerView, regexp.MustCompile(`(?i)\bview\b|\bdetails?\b|\bopen\b|\bshow\b|\bpreview\b|查看|详情|詳情`)},
	{unlockTriggerList, regexp.MustCompile(`(?i)\blist\b|\ball\b|\bnext\b|\bmore\b|列表|全部|下一页|更多`)},
}

// unlockListRoleRe marks a control the app renders as navigation: a tab, a
// menu entry.
var unlockListRoleRe = regexp.MustCompile(`(?i)(?:^| )role=(?:tab|menuitem|link)\b`)

// unlockSearchInputRe marks a search field's submit control.
var unlockSearchInputRe = regexp.MustCompile(`(?i)(?:^| )type=search\b`)

// unlockTriggerKind classifies one control by what a person would read it
// as, its role and whether it is a link.
func unlockTriggerKind(label, attrs, tag, href string) string {
	for _, t := range unlockTriggerRes {
		if t.re.MatchString(label) {
			return t.kind
		}
	}
	switch {
	case unlockSearchInputRe.MatchString(attrs):
		return unlockTriggerSearch
	case unlockListRoleRe.MatchString(attrs), strings.EqualFold(tag, "a") && href != "":
		return unlockTriggerList
	}
	return unlockTriggerOther
}

// unlockClickCandidate is one control the planner may choose.
type unlockClickCandidate struct {
	kind  string
	label string
	el    *action.CandidateElement
}

// planUnlockClicks orders at most limit candidates: the first of each
// one-per-kind trigger, then links, tabs and other controls with a label not
// yet chosen, in extraction order.
func planUnlockClicks(cands []unlockClickCandidate, limit int) []unlockClickCandidate {
	if limit <= 0 {
		return nil
	}
	var out []unlockClickCandidate
	taken := make([]bool, len(cands))
	for _, kind := range unlockOnePerKind {
		for i, c := range cands {
			if c.kind == kind {
				out, taken[i] = append(out, c), true
				break
			}
		}
	}
	labels := map[string]bool{}
	for _, c := range out {
		labels[strings.ToLower(c.label)] = true
	}
	for i, c := range cands {
		if taken[i] || (c.kind != unlockTriggerList && c.kind != unlockTriggerOther) {
			continue
		}
		key := strings.ToLower(c.label)
		if labels[key] {
			continue
		}
		labels[key] = true
		out = append(out, c)
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// clickBudget is how many controls the walk clicks per route and, when that
// is zero although the profile allows clicks, why.
func (w *unlockWalk) clickBudget() (int, string) {
	n := w.profile.ClicksPerRoute()
	if n <= 0 {
		return 0, ""
	}
	if w.cfg.AllowWrites {
		return 0, "writes_allowed"
	}
	return n, ""
}

// unlockClicker clicks one walk's routes with one candidate extractor.
type unlockClicker struct {
	w     *unlockWalk
	ext   *action.CandidateElementExtractor
	limit int
}

// newClicker is the walk's clicker, nil when the walk clicks nothing.
func (w *unlockWalk) newClicker() *unlockClicker {
	n, _ := w.clickBudget()
	if n == 0 {
		return nil
	}
	cfg, err := config.New(w.origin.String() + "/")
	if err != nil {
		return nil
	}
	// The walk's own document only: a frame's controls are rarely a module's
	// triggers, and each frame costs an extraction pass.
	cfg.CrawlFrames = false
	cfg.ClickOnce = false
	cfg.RandomizeElements = false
	return &unlockClicker{w: w, ext: action.NewCandidateElementExtractor(cfg), limit: n}
}

// clickRoute clicks the planned controls of the route the page shows and
// returns the text the page settles on. A route the guard redirected, or that
// failed to load, is not clicked: its controls are the gate's, not the view's.
func (c *unlockClicker) clickRoute(ctx context.Context, page *browser.Page, target *url.URL, settle time.Duration, text string, r *UnlockRouteResult) string {
	if r.Redirected || r.Error != "" {
		return text
	}
	w := c.w
	skippedBefore := c.ext.SkippedDestructive()
	found, err := c.ext.Extract(ctx, page)
	r.ClicksSkippedDestructive = int(c.ext.SkippedDestructive() - skippedBefore)
	if err != nil || len(found) == 0 {
		return text
	}
	cands := make([]unlockClickCandidate, 0, len(found))
	for _, el := range found {
		if el == nil || el.EventType != action.EventTypeClick || el.RelatedFrame != "" || el.Identification == nil {
			continue
		}
		label := el.Label()
		cands = append(cands, unlockClickCandidate{kind: unlockTriggerKind(label, el.Attributes, el.TagName, el.Href), label: label, el: el})
	}
	plan := planUnlockClicks(cands, c.limit)
	if len(plan) == 0 {
		return text
	}

	idx := w.current.Load()
	w.clicking.Store(true)
	defer w.clicking.Store(false)
	wait := min(settle, unlockClickSettle)
	for _, cc := range plan {
		if ctx.Err() != nil {
			break
		}
		before := w.bucketSize(idx)
		click := UnlockClick{Kind: cc.kind, Label: cc.label}
		if err := clickUnlockCandidate(page, cc.el); err != nil {
			click.Error = err.Error()
		} else {
			settlePage(page, wait)
		}
		_, _ = page.EvalWithArgs(unlockDismissScript)
		click.Requests = w.bucketSize(idx) - before
		if final, _ := page.URL(); final != "" && !sameRouteTarget(target, final) {
			click.LeftRoute = final
			if nerr := page.NavigateCtx(ctx, target.String()); nerr == nil {
				settlePage(page, settle)
			}
		}
		r.Clicks = append(r.Clicks, click)
	}
	return pageText(page)
}

// unlockDismissScript closes what a click opened over the view (a modal, a
// drawer, a dropdown) with the Escape key most UI kits listen for.
const unlockDismissScript = `() => {
  const t = document.activeElement || document.body || document;
  for (const type of ['keydown', 'keyup']) {
    t.dispatchEvent(new KeyboardEvent(type, { key: 'Escape', code: 'Escape', keyCode: 27, bubbles: true }));
  }
  return true;
}`

// clickUnlockCandidate finds the candidate's element again (by XPath, or by
// the locator a shadow-DOM element carries) and clicks it.
func clickUnlockCandidate(page *browser.Page, c *action.CandidateElement) error {
	id := c.Identification
	var (
		el  *browser.Element
		err error
	)
	if id.How == action.HowXPath {
		el, err = page.ElementX(id.Value)
	} else {
		el, err = page.Element(id.Value)
	}
	if err != nil {
		return fmt.Errorf("element not found: %w", err)
	}
	return el.Click()
}
