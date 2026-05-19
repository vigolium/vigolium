package browser

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// maxRecordedDialogs caps per-page dialog history so a malicious page can't
// drive memory growth by spamming alert() calls.
const maxRecordedDialogs = 64

// DialogEvent describes a JavaScript dialog (alert/confirm/prompt/beforeunload)
// that opened on the page. Captured by setupAutoDialogHandler before the
// dialog is auto-accepted, so consumers can confirm XSS by observing fired
// alerts without blocking the page.
type DialogEvent struct {
	Type    string    // "alert", "confirm", "prompt", "beforeunload"
	Message string    // The dialog message text
	URL     string    // Frame URL where the dialog originated
	At      time.Time // When the dialog opened
}

// Page wraps rod.Page with additional functionality.
type Page struct {
	rodPage *rod.Page
	config  *config.Config
	browser *Browser

	dialogMu sync.Mutex
	dialogs  []DialogEvent
}

// Navigate navigates to a URL with timeout.
func (p *Page) Navigate(url string) error {
	if err := p.rodPage.Timeout(p.config.PageLoadTimeout).Navigate(url); err != nil {
		return fmt.Errorf("failed to navigate to %s: %w", url, err)
	}

	// Wait for page to load
	if err := p.WaitStable(p.config.DOMStableTime); err != nil {
		// Non-fatal, log and continue
		time.Sleep(p.config.DOMStableTime)
	}

	return nil
}

// Reload reloads the current page with timeout.
func (p *Page) Reload() error {
	if err := p.rodPage.Timeout(p.config.PageLoadTimeout).Reload(); err != nil {
		return fmt.Errorf("failed to reload: %w", err)
	}

	if err := p.WaitStable(p.config.WaitAfterReload); err != nil {
		time.Sleep(p.config.WaitAfterReload)
	}

	return nil
}

// sleepWithContext sleeps for duration d but returns early if ctx is cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// NavigateCtx navigates to a URL with timeout, capping rod timeout to remaining context deadline.
func (p *Page) NavigateCtx(ctx context.Context, url string) error {
	timeout := p.config.PageLoadTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ctx.Err()
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	if err := p.rodPage.Timeout(timeout).Navigate(url); err != nil {
		return fmt.Errorf("failed to navigate to %s: %w", url, err)
	}
	if err := p.WaitStable(p.config.DOMStableTime); err != nil {
		if ctxErr := sleepWithContext(ctx, p.config.DOMStableTime); ctxErr != nil {
			return ctxErr
		}
	}
	return nil
}

// ReloadCtx reloads the current page with timeout, capping rod timeout to remaining context deadline.
func (p *Page) ReloadCtx(ctx context.Context) error {
	timeout := p.config.PageLoadTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ctx.Err()
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	if err := p.rodPage.Timeout(timeout).Reload(); err != nil {
		return fmt.Errorf("failed to reload: %w", err)
	}
	if err := p.WaitStable(p.config.WaitAfterReload); err != nil {
		if ctxErr := sleepWithContext(ctx, p.config.WaitAfterReload); ctxErr != nil {
			return ctxErr
		}
	}
	return nil
}

// URL returns the current page URL.
func (p *Page) URL() (string, error) {
	info, err := p.rodPage.Timeout(p.config.PageLoadTimeout).Info()
	if err != nil {
		return "", err
	}
	return info.URL, nil
}

// HTML returns the page HTML.
func (p *Page) HTML() (string, error) {
	return p.rodPage.Timeout(p.config.PageLoadTimeout).HTML()
}

// WaitStable waits for the page to be stable.
func (p *Page) WaitStable(d time.Duration) error {
	if d == 0 {
		d = 500 * time.Millisecond
	}
	return p.rodPage.Timeout(p.config.PageLoadTimeout).WaitStable(d)
}

// WaitLoad waits for the page to finish loading with timeout.
func (p *Page) WaitLoad() error {
	return p.rodPage.Timeout(p.config.PageLoadTimeout).WaitLoad()
}

// WaitElement waits for an element to exist.
func (p *Page) WaitElement(selector string, timeout time.Duration) error {
	rodPage := p.rodPage.Timeout(timeout)
	_, err := rodPage.Element(selector)
	return err
}

// WaitVisible waits for an element to be visible.
func (p *Page) WaitVisible(selector string, timeout time.Duration) error {
	rodPage := p.rodPage.Timeout(timeout)
	elem, err := rodPage.Element(selector)
	if err != nil {
		return err
	}
	return elem.WaitVisible()
}

// SetCookies sets cookies on the page from http.Cookie slice.
// Converts net/http cookies to rod's NetworkCookieParam format.
func (p *Page) SetCookies(cookies []*http.Cookie) error {
	if len(cookies) == 0 {
		return nil
	}

	// Get target URL from config for setting cookies before navigation
	var targetURL string
	if p.config != nil && p.config.URL != nil {
		targetURL = p.config.URL.String()
	}

	// Convert http.Cookie to proto.NetworkCookieParam
	params := make([]*proto.NetworkCookieParam, 0, len(cookies))
	for _, c := range cookies {
		// Map SameSite from http to proto
		sameSite := proto.NetworkCookieSameSiteLax // Default
		switch c.SameSite {
		case http.SameSiteStrictMode:
			sameSite = proto.NetworkCookieSameSiteStrict
		case http.SameSiteNoneMode:
			sameSite = proto.NetworkCookieSameSiteNone
		}

		param := &proto.NetworkCookieParam{
			Name:     c.Name,
			Value:    c.Value,
			URL:      targetURL, // Use URL instead of Domain for pre-navigation cookies
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			SameSite: sameSite,
		}

		// Set expiry if present
		if !c.Expires.IsZero() {
			expires := proto.TimeSinceEpoch(c.Expires.Unix())
			param.Expires = expires
		}

		params = append(params, param)
	}

	return p.rodPage.SetCookies(params)
}

// Element finds an element by CSS selector with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (p *Page) Element(selector string) (*Element, error) {
	rodElem, err := p.rodPage.Timeout(p.config.ElementTimeout).Element(selector)
	if err != nil {
		return nil, err
	}
	return &Element{rodElem: rodElem, page: p}, nil
}

// Elements finds all elements matching a CSS selector with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (p *Page) Elements(selector string) ([]*Element, error) {
	rodElems, err := p.rodPage.Timeout(p.config.ElementTimeout).Elements(selector)
	if err != nil {
		return nil, err
	}

	elements := make([]*Element, len(rodElems))
	for i, re := range rodElems {
		elements[i] = &Element{rodElem: re, page: p}
	}
	return elements, nil
}

// ElementX finds an element by XPath with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (p *Page) ElementX(xpath string) (*Element, error) {
	rodElem, err := p.rodPage.Timeout(p.config.ElementTimeout).ElementX(xpath)
	if err != nil {
		return nil, err
	}
	return &Element{rodElem: rodElem, page: p}, nil
}

// ElementsX finds all elements matching an XPath with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (p *Page) ElementsX(xpath string) ([]*Element, error) {
	rodElems, err := p.rodPage.Timeout(p.config.ElementTimeout).ElementsX(xpath)
	if err != nil {
		return nil, err
	}

	elements := make([]*Element, len(rodElems))
	for i, re := range rodElems {
		elements[i] = &Element{rodElem: re, page: p}
	}
	return elements, nil
}

// Click clicks an element by selector.
func (p *Page) Click(selector string) error {
	elem, err := p.Element(selector)
	if err != nil {
		return err
	}
	return elem.Click()
}

// Hover hovers over an element by selector.
func (p *Page) Hover(selector string) error {
	elem, err := p.Element(selector)
	if err != nil {
		return err
	}
	return elem.Hover()
}

// Eval evaluates JavaScript expression on the page.
// Uses CDP RuntimeEvaluate directly to support arbitrary expressions (not just functions).
func (p *Page) Eval(script string) (interface{}, error) {
	result, err := proto.RuntimeEvaluate{
		Expression:            script,
		IncludeCommandLineAPI: true,
		ReturnByValue:         true,
	}.Call(p.rodPage)

	if err != nil {
		return nil, err
	}

	if result.ExceptionDetails != nil {
		return nil, fmt.Errorf("eval error: %s", result.ExceptionDetails.Text)
	}

	return result.Result.Value.Val(), nil
}

// EvalWithArgs evaluates JavaScript with arguments.
func (p *Page) EvalWithArgs(script string, args ...interface{}) (interface{}, error) {
	result, err := p.rodPage.Evaluate(rod.Eval(script, args...))
	if err != nil {
		return nil, err
	}
	return result.Value.Val(), nil
}

// EvalCDP executes a CDP command via Runtime.evaluate.
func (p *Page) EvalCDP(expression string) (interface{}, error) {
	result, err := proto.RuntimeEvaluate{
		Expression:            expression,
		IncludeCommandLineAPI: true,
		ReturnByValue:         true,
	}.Call(p.rodPage)

	if err != nil {
		return nil, err
	}

	if result.ExceptionDetails != nil {
		return nil, fmt.Errorf("CDP eval exception: %s", result.ExceptionDetails.Text)
	}

	return result.Result.Value.Val(), nil
}

// ExecuteCDP runs a CDP command directly.
func (p *Page) ExecuteCDP(method string, params map[string]interface{}) (interface{}, error) {
	// This would require direct CDP access through rod
	// For now, use Eval as workaround
	return nil, fmt.Errorf("ExecuteCDP not implemented - use EvalCDP instead")
}

// Screenshot takes a viewport screenshot as PNG.
func (p *Page) Screenshot() ([]byte, error) {
	return p.rodPage.Screenshot(false, nil)
}

// FullScreenshot takes a full page screenshot as PNG.
func (p *Page) FullScreenshot() ([]byte, error) {
	return p.rodPage.Screenshot(true, nil)
}

// ScreenshotCompact captures a viewport screenshot as JPEG at reduced quality.
// Optimized for AI agent consumption: small file size, sufficient visual fidelity.
func (p *Page) ScreenshotCompact(quality int) ([]byte, error) {
	return p.rodPage.Screenshot(false, &proto.PageCaptureScreenshot{
		Format:           proto.PageCaptureScreenshotFormatJpeg,
		Quality:          &quality,
		OptimizeForSpeed: true,
	})
}

// Close closes the page.
func (p *Page) Close() error {
	return p.rodPage.Close()
}

// Browser returns the parent browser.
func (p *Page) Browser() *Browser {
	return p.browser
}

// RodPage returns the underlying rod.Page (for advanced usage).
func (p *Page) RodPage() *rod.Page {
	return p.rodPage
}

// Title returns the page title.
func (p *Page) Title() (string, error) {
	info, err := p.rodPage.Timeout(p.config.PageLoadTimeout).Info()
	if err != nil {
		return "", err
	}
	return info.Title, nil
}

// NavigateBack navigates back in history and waits for navigation to complete.
func (p *Page) NavigateBack() error {
	// Setup wait BEFORE triggering navigation with timeout
	// Use PageLoadTimeout to prevent infinite waiting
	wait := p.rodPage.Timeout(p.config.PageLoadTimeout).WaitNavigation(proto.PageLifecycleEventNameNetworkAlmostIdle)

	// Trigger back navigation
	if err := p.rodPage.NavigateBack(); err != nil {
		return err
	}

	// Wait for navigation to complete (with timeout)
	wait()

	return nil
}

// NavigateForward navigates forward in history with timeout.
func (p *Page) NavigateForward() error {
	return p.rodPage.Timeout(p.config.PageLoadTimeout).NavigateForward()
}

// SetViewport sets the page viewport size.
func (p *Page) SetViewport(width, height int) error {
	return p.rodPage.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width:  width,
		Height: height,
	})
}

// WaitDOMStable waits for DOM to be stable.
func (p *Page) WaitDOMStable(d time.Duration, diff float64) error {
	return p.rodPage.Timeout(p.config.PageLoadTimeout).WaitDOMStable(d, diff)
}

// HasElement checks if an element exists.
func (p *Page) HasElement(selector string) bool {
	_, err := p.rodPage.Timeout(100 * time.Millisecond).Element(selector)
	return err == nil
}

// HasElementX checks if an element exists by XPath.
func (p *Page) HasElementX(xpath string) bool {
	_, err := p.rodPage.Timeout(100 * time.Millisecond).ElementX(xpath)
	return err == nil
}

// Frames returns all iframe elements in the page with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (p *Page) Frames() ([]*Page, error) {
	iframes, err := p.rodPage.Timeout(p.config.ElementTimeout).Elements("iframe")
	if err != nil {
		return nil, err
	}

	frames := make([]*Page, 0, len(iframes))
	for _, iframe := range iframes {
		if !frameAccessible(iframe) {
			continue
		}
		framePage, err := iframe.Frame()
		if err != nil {
			continue // Skip iframes that can't be accessed
		}
		frames = append(frames, &Page{rodPage: framePage, config: p.config, browser: p.browser})
	}
	return frames, nil
}

// frameAccessible returns true if the iframe has a usable content document.
// Cross-origin or detached iframes return ContentDocument == nil from CDP, and
// rod's lazy getJSCtxID() panics when it dereferences that nil pointer the first
// time we touch the resulting frame Page. We pre-filter here with a cheap
// Describe(pierce=true) call so cross-origin frames are skipped up front
// rather than crashing later.
func frameAccessible(iframe *rod.Element) bool {
	node, err := iframe.Describe(1, true)
	if err != nil {
		return false
	}
	return node.ContentDocument != nil
}

// FrameInfo contains information about an iframe.
type FrameInfo struct {
	Page  *Page  // The frame's page object
	ID    string // Frame id or name (empty if neither exists)
	Index int    // Index in parent's iframe list
}

// FramesWithInfo returns all iframe elements with their identification info.
func (p *Page) FramesWithInfo() ([]FrameInfo, error) {
	iframes, err := p.rodPage.Timeout(p.config.ElementTimeout).Elements("iframe")
	if err != nil {
		return nil, err
	}

	frames := make([]FrameInfo, 0, len(iframes))
	for i, iframe := range iframes {
		if !frameAccessible(iframe) {
			continue
		}
		framePage, err := iframe.Frame()
		if err != nil {
			continue // Skip iframes that can't be accessed
		}

		idPtr, _ := iframe.Attribute("id")
		namePtr, _ := iframe.Attribute("name")

		frameID := ""
		if idPtr != nil && *idPtr != "" && *idPtr != "<nil>" {
			frameID = *idPtr
		} else if namePtr != nil && *namePtr != "" && *namePtr != "<nil>" {
			frameID = *namePtr
		}

		frames = append(frames, FrameInfo{
			Page:  &Page{rodPage: framePage, config: p.config, browser: p.browser},
			ID:    frameID,
			Index: i,
		})
	}
	return frames, nil
}

// HTMLWithFrames returns the page HTML with all iframe content embedded.
// builds a combined DOM by importing frame content into iframe elements.
// This is critical for proper state comparison when content changes in iframes.
func (p *Page) HTMLWithFrames() (string, error) {
	return p.htmlWithFramesRecursive("", make(map[string]bool))
}

// htmlWithFramesRecursive recursively builds HTML with frame content.
// This approach is simpler than DOM manipulation and works for state comparison.
func (p *Page) htmlWithFramesRecursive(parentFramePath string, visited map[string]bool) (string, error) {
	mainHTML, err := p.rodPage.HTML()
	if err != nil {
		return "", err
	}

	// Get all iframes with their info
	frameInfos, err := p.FramesWithInfo()
	if err != nil {
		return mainHTML, nil // Return main HTML if can't get frames
	}

	// Collect frame HTML parts
	var frameParts []string
	for _, fi := range frameInfos {
		// Build frame identification
		frameIdent := fi.ID
		if frameIdent == "" {
			frameIdent = fmt.Sprintf("frame%d", fi.Index)
		}

		// Build full frame path
		fullPath := frameIdent
		if parentFramePath != "" {
			fullPath = parentFramePath + "." + frameIdent
		}

		// Avoid infinite recursion
		if visited[fullPath] {
			continue
		}
		visited[fullPath] = true

		// Get frame content recursively
		frameHTML, err := fi.Page.htmlWithFramesRecursive(fullPath, visited)
		if err != nil {
			continue
		}

		// Simply append frame HTML (no markers that could cause spurious state differences)
		frameParts = append(frameParts, frameHTML)
	}

	// Combine main HTML with frame HTML
	if len(frameParts) > 0 {
		return mainHTML + strings.Join(frameParts, ""), nil
	}
	return mainHTML, nil
}

// HTMLWithFramesFiltered returns HTML with frame content, respecting ignore patterns.
func (p *Page) HTMLWithFramesFiltered(crawlFrames bool, ignorePatterns []string) (string, error) {
	if !crawlFrames {
		// If frame crawling is disabled, return just the main page HTML
		return p.rodPage.HTML()
	}
	return p.htmlWithFramesFilteredRecursive("", make(map[string]bool), ignorePatterns)
}

// htmlWithFramesFilteredRecursive recursively builds HTML with filtered frame content.
func (p *Page) htmlWithFramesFilteredRecursive(parentFramePath string, visited map[string]bool, ignorePatterns []string) (string, error) {
	mainHTML, err := p.rodPage.HTML()
	if err != nil {
		return "", err
	}

	// Get all iframes with their info
	frameInfos, err := p.FramesWithInfo()
	if err != nil {
		return mainHTML, nil
	}

	var frameParts []string
	for _, fi := range frameInfos {
		// Build frame identification
		frameIdent := fi.ID
		if frameIdent == "" {
			frameIdent = fmt.Sprintf("frame%d", fi.Index)
		}

		// Build full frame path
		fullPath := frameIdent
		if parentFramePath != "" {
			fullPath = parentFramePath + "." + frameIdent
		}

		// Check if frame should be ignored
		if isFrameIgnored(fullPath, ignorePatterns) {
			continue
		}

		// Avoid infinite recursion
		if visited[fullPath] {
			continue
		}
		visited[fullPath] = true

		// Get frame content recursively
		frameHTML, err := fi.Page.htmlWithFramesFilteredRecursive(fullPath, visited, ignorePatterns)
		if err != nil {
			continue
		}

		// Simply append frame HTML
		frameParts = append(frameParts, frameHTML)
	}

	// Combine main HTML with frame HTML
	if len(frameParts) > 0 {
		return mainHTML + strings.Join(frameParts, ""), nil
	}
	return mainHTML, nil
}

// isFrameIgnored checks if a frame should be ignored based on patterns.
// Pattern matching: "%" is treated as wildcard (replaced with ".*" for regex)
// Go version uses "*" as wildcard for consistency with glob patterns.
func isFrameIgnored(frameIdent string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchesFramePattern(pattern, frameIdent) {
			return true
		}
	}
	return false
}

// matchesFramePattern checks if frameIdent matches the pattern.
// Supports wildcard: "*" matches any characters, "%" also supported.
func matchesFramePattern(pattern, frameIdent string) bool {
	// Handle both "*" (Go style) and "%" wildcards
	if strings.Contains(pattern, "%") || strings.Contains(pattern, "*") {
		// Convert to regex pattern
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, "\\%", ".*")
		regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")
		matched, _ := regexp.MatchString(regexPattern, frameIdent)
		return matched
	}
	// Exact match
	return pattern == frameIdent
}

// setupAutoDialogHandler sets up automatic dialog handling for alert/confirm/prompt.
// Must be called when page is created to ensure dialogs don't block crawl.
// The handler runs in a background goroutine: it records the event so XSS
// confirmation can observe it, then auto-accepts the dialog.
func (p *Page) setupAutoDialogHandler() {
	// Enable Page domain for dialog events
	_ = proto.PageEnable{}.Call(p.rodPage)

	// Start background goroutine to handle all dialogs.
	// Callback returns bool: false = keep listening, true = stop.
	go p.rodPage.EachEvent(func(e *proto.PageJavascriptDialogOpening) bool {
		p.recordDialog(DialogEvent{
			Type:    string(e.Type),
			Message: e.Message,
			URL:     e.URL,
			At:      time.Now(),
		})
		_ = proto.PageHandleJavaScriptDialog{
			Accept:     true,
			PromptText: "",
		}.Call(p.rodPage)
		return false
	})()
}

// recordDialog appends a dialog event to the page log, dropping the oldest
// entry once the cap is hit so memory stays bounded.
func (p *Page) recordDialog(ev DialogEvent) {
	p.dialogMu.Lock()
	defer p.dialogMu.Unlock()
	if len(p.dialogs) >= maxRecordedDialogs {
		copy(p.dialogs, p.dialogs[1:])
		p.dialogs = p.dialogs[:len(p.dialogs)-1]
	}
	p.dialogs = append(p.dialogs, ev)
}

// DialogEvents returns a copy of all dialog events recorded on this page.
// Safe for concurrent use.
func (p *Page) DialogEvents() []DialogEvent {
	p.dialogMu.Lock()
	defer p.dialogMu.Unlock()
	if len(p.dialogs) == 0 {
		return nil
	}
	out := make([]DialogEvent, len(p.dialogs))
	copy(out, p.dialogs)
	return out
}

// DrainDialogs returns all recorded dialog events and clears the log.
// Use when you want "events since last drain" semantics.
func (p *Page) DrainDialogs() []DialogEvent {
	p.dialogMu.Lock()
	defer p.dialogMu.Unlock()
	if len(p.dialogs) == 0 {
		return nil
	}
	out := p.dialogs
	p.dialogs = nil
	return out
}

// HandlePopups handles any alert/confirm/prompt dialogs on the page.
// Note: Auto-dialog handler is already set up in setupAutoDialogHandler().
// This method is kept for manual dialog handling if needed.
func (p *Page) HandlePopups() error {
	// Dialog handler is already running in background from setupAutoDialogHandler()
	// This method can be used to trigger immediate check if needed
	return nil
}

// DismissDialog dismisses any currently open dialog.
func (p *Page) DismissDialog() error {
	return proto.PageHandleJavaScriptDialog{
		Accept: false, // Dismiss/cancel
	}.Call(p.rodPage)
}

// AcceptDialog accepts any currently open dialog.
func (p *Page) AcceptDialog(promptText string) error {
	return proto.PageHandleJavaScriptDialog{
		Accept:     true,
		PromptText: promptText,
	}.Call(p.rodPage)
}

// HandleFileDialog enables file chooser interception and returns a handler function.
// Call the returned function with file paths after triggering the file dialog.
// GO EXTENSION: Intercepts OS file chooser dialog for any file upload trigger.
//
// Usage:
//
//	handler, err := page.HandleFileDialog()
//	// Click button/element that opens file dialog
//	button.Click()
//	// Provide files to the intercepted dialog
//	err = handler([]string{"/path/to/file.png"})
func (p *Page) HandleFileDialog() (func([]string) error, error) {
	return p.rodPage.HandleFileDialog()
}
