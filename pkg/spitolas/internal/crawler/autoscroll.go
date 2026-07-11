package crawler

import (
	"context"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// autoScrollMaxSteps / autoScrollStepMs bound the in-page scroll sweep: step down
// by a viewport at a time, pausing between steps so each section's lazy fetch can
// fire before the next scroll. ~20 viewports covers a long content landing.
const (
	autoScrollMaxSteps = 20
	autoScrollStepMs   = 400
)

// autoScrollTimeout bounds the whole in-page scroll eval so a pathological page
// (e.g. one whose scrollHeight keeps growing) cannot stall the crawl.
const autoScrollTimeout = 20 * time.Second

// autoScrollScript scrolls the window down a viewport at a time to the bottom
// (then back to the top), dispatching a scroll event each step and pausing so
// IntersectionObserver-gated content and scroll-triggered data fetches have time
// to fire. It also nudges the innermost scrollable container, since some apps
// scroll an element rather than the window. %d is max steps, %d is the per-step
// pause in ms. No backticks: embedded as a Go raw string.
const autoScrollScript = `(async () => {
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const maxSteps = %d, stepMs = %d;
  const docH = () => Math.max(
    document.body ? document.body.scrollHeight : 0,
    document.documentElement ? document.documentElement.scrollHeight : 0,
    window.innerHeight);
  // Largest scrollable element (some SPAs scroll a container, not the window).
  let container = null, best = 0;
  try {
    for (const el of document.querySelectorAll('*')) {
      const ov = getComputedStyle(el).overflowY;
      if ((ov === 'auto' || ov === 'scroll') && el.scrollHeight - el.clientHeight > best) {
        best = el.scrollHeight - el.clientHeight; container = el;
      }
    }
  } catch (e) {}
  let steps = 0, y = 0;
  while (steps < maxSteps) {
    const prev = window.scrollY;
    y = Math.min(y + window.innerHeight, docH());
    window.scrollTo(0, y);
    if (container) { try { container.scrollTop = Math.min(container.scrollTop + container.clientHeight, container.scrollHeight); } catch (e) {} }
    try { window.dispatchEvent(new Event('scroll')); } catch (e) {}
    await sleep(stepMs);
    steps++;
    if (y >= docH() - window.innerHeight && window.scrollY <= prev) break; // reached the bottom
  }
  window.scrollTo(0, 0);
  return steps;
})()`

// scrollToLoadContent scrolls the page through its height so content/assets that
// load lazily on scroll are requested and captured, then waits for the resulting
// fetches to settle. Best-effort: any failure is logged at debug and the crawl
// continues. Bounded by autoScrollTimeout (eval) and SPASettleTimeout (settle).
func (c *Crawler) scrollToLoadContent(ctx context.Context, page *browser.Page) {
	if page == nil || c.config == nil || !c.config.AutoScroll {
		return
	}
	if ctx.Err() != nil {
		return
	}
	script := fmt.Sprintf(autoScrollScript, autoScrollMaxSteps, autoScrollStepMs)
	steps, err := page.EvalAwait(script, autoScrollTimeout)
	if err != nil {
		zap.L().Debug("Auto-scroll failed", zap.Error(err))
		return
	}
	zap.L().Debug("Auto-scrolled page to trigger lazy content", zap.Any("steps", steps))

	// Let the fetches and images the scroll triggered land in the network capture.
	page.WaitNetworkIdle(c.config.DOMStableTime, c.config.SPASettleTimeout)
}

// pageBelowFoldScript reports whether the page has content below the initial
// viewport (taller than the fold) OR carries lazy-load markers — either means a
// scroll sweep can still reveal content/assets. A page that fits on screen with
// no lazy markers has nothing to reveal, so the caller can skip the scroll.
const pageBelowFoldScript = `(function(){
  var d = document.documentElement, b = document.body;
  var h = Math.max(d ? d.scrollHeight : 0, b ? b.scrollHeight : 0);
  if (h > window.innerHeight + 64) return true;
  return !!document.querySelector('[loading=lazy],[data-src],[data-lazy],[data-bg],[data-background]');
})()`

// settleNewState gives a newly discovered SPA state the same lazy-content
// treatment the index page gets, but proportional to the work there is to do: it
// lets the route change's bootstrap XHRs quiesce (an activity-driven network-idle
// settle that returns immediately when the state is already quiet) and only pays
// the scroll sweep when the state actually has content below the fold or lazy
// markers. Without this, states reached mid-crawl captured only their above-the-
// fold shell, missing lazy routes and infinite-scroll data deeper in the app.
func (c *Crawler) settleNewState(ctx context.Context, page *browser.Page) {
	if page == nil || c.config == nil || ctx.Err() != nil {
		return
	}
	c.settleSPA(ctx, page)
	if !c.config.AutoScroll || ctx.Err() != nil {
		return
	}
	val, err := page.Eval(pageBelowFoldScript)
	if err != nil {
		return
	}
	if below, _ := val.(bool); below {
		c.scrollToLoadContent(ctx, page)
	}
}
