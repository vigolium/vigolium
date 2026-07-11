// Package action provides web crawling action types and handling.
package action

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// File download patterns - skip these hrefs.
var fileDownloadPattern = regexp.MustCompile(`(?i)\.(?:pdf|ps|zip|gz|tar|rar|7z|mp3|mp4|avi|mov|wmv|doc|docx|xls|xlsx|ppt|pptx)(?:$|\?|#)`)

// FormHandler interface for form input handling.
type FormHandler interface {
	// GetCandidateElementsForInputs generates candidate element variants
	// with different form input values for the given element and condition.
	// Returns the original candidate if no combinations are needed.
	GetCandidateElementsForInputs(elementXPath string, baseCandidate *CandidateElement) []*CandidateElement

	// GetFormInputs returns all form inputs from the current page.
	GetFormInputs() []*FormInput

	// HandleFormElements fills in form/input elements.
	// Returns the list of form inputs that were handled.
	HandleFormElements(formInputs []*FormInput) []*FormInput
}

// CandidateElementExtractor extracts candidate elements from the DOM tree.
type CandidateElementExtractor struct {
	// Configuration for element extraction
	clickSelectors      []string
	excludeSelectors    []string
	useCDP              bool
	followExternalLinks bool
	siteHost            string // Host of target site for external link detection
	crawlConditions     []config.ConditionConfig
	randomizeElements   bool     // Randomize order of extracted elements
	crawlFrames         bool     // Enable recursive frame extraction
	frameIgnorePatterns []string // Patterns to ignore frames by name/id

	formHandler FormHandler

	checkedElements ExtractorManager

	// Internal clickOnce tracking (when no ExtractorManager is provided)
	clickOnce      bool
	clickOnceSeen  map[string]bool
	clickOnceMutex sync.RWMutex
	// currentStateID namespaces clickOnce dedup by the state being extracted, so
	// the SAME element location in a DIFFERENT state (a multi-step form / wizard
	// reusing one "Next" button position across steps) is treated as new rather
	// than globally suppressed. Set via SetCurrentState before each Extract.
	currentStateID string
}

// NewCandidateElementExtractor creates a new CandidateElementExtractor.
func NewCandidateElementExtractor(cfg *config.Config) *CandidateElementExtractor {
	host := ""
	if cfg.URL != nil {
		host = strings.ToLower(cfg.URL.Host)
	}

	// - ExcludeSelectors: direct CSS selectors to exclude
	excludeSelectors := make([]string, 0, len(cfg.ExcludeSelectors)+len(cfg.DontClickSelectors)+len(cfg.DontClickChildrenOfSelectors))
	excludeSelectors = append(excludeSelectors, cfg.ExcludeSelectors...)
	excludeSelectors = append(excludeSelectors, cfg.DontClickSelectors...)
	// For dontClickChildrenOf, we need to exclude all descendants
	for _, parentSelector := range cfg.DontClickChildrenOfSelectors {
		// Exclude direct children and all descendants
		excludeSelectors = append(excludeSelectors, parentSelector+" *")
	}

	return &CandidateElementExtractor{
		clickSelectors:      cfg.ClickSelectors,
		excludeSelectors:    excludeSelectors,
		useCDP:              cfg.UseCDPDetection,
		followExternalLinks: false, // Default: don't follow external links
		siteHost:            host,
		crawlConditions:     cfg.CrawlConditions,
		randomizeElements:   cfg.RandomizeElements,
		crawlFrames:         cfg.CrawlFrames,
		frameIgnorePatterns: cfg.ExcludeFrames,
		clickOnce:           cfg.ClickOnce,
		clickOnceSeen:       make(map[string]bool),
	}
}

// NewCandidateElementExtractorDefault creates an extractor with default settings.
func NewCandidateElementExtractorDefault() *CandidateElementExtractor {
	return &CandidateElementExtractor{
		clickSelectors:      config.DefaultClickSelectors(),
		excludeSelectors:    []string{},
		useCDP:              true,
		followExternalLinks: false,
		siteHost:            "",
		crawlConditions:     nil,
		randomizeElements:   false,
		crawlFrames:         true,
		frameIgnorePatterns: []string{},
		clickOnce:           false, // Default: allow same element from different states
		clickOnceSeen:       make(map[string]bool),
	}
}

// SetFollowExternalLinks sets whether to follow external links.
func (e *CandidateElementExtractor) SetFollowExternalLinks(follow bool) {
	e.followExternalLinks = follow
}

// SetClickOnce enables or disables element deduplication.
func (e *CandidateElementExtractor) SetClickOnce(enabled bool) {
	e.clickOnceMutex.Lock()
	defer e.clickOnceMutex.Unlock()
	e.clickOnce = enabled
}

// SetCurrentState sets the state ID that subsequent extractions belong to, so
// clickOnce dedup is scoped per-state. Passing "" restores un-namespaced dedup.
// The single-threaded crawler sets this before each Extract from its own
// goroutine; the lock keeps it race-clean.
func (e *CandidateElementExtractor) SetCurrentState(stateID string) {
	e.clickOnceMutex.Lock()
	defer e.clickOnceMutex.Unlock()
	e.currentStateID = stateID
}

// markChecked checks if an element was already extracted and marks it as checked.
// Returns true if the element is NEW (should be extracted), false if already seen.
func (e *CandidateElementExtractor) markChecked(candidate *CandidateElement) bool {
	if !e.clickOnce {
		return true // Always extract when clickOnce is disabled
	}

	e.clickOnceMutex.Lock()
	defer e.clickOnceMutex.Unlock()

	// Namespace the element key by the current state so the same element location
	// in a different state (a wizard/multi-step form reusing one "Next" button
	// position) is NOT globally suppressed — the old key was state-independent,
	// which silently dropped later steps of such flows. EventType is included so a
	// hover-menu action and a click action on the SAME element coexist (a nav
	// trigger that both clicks through and opens a submenu on hover).
	key := e.currentStateID + "\x00" + string(candidate.EventType) + "\x00" + candidate.GetUniqueString()
	if e.clickOnceSeen[key] {
		return false // Already extracted in this state
	}
	e.clickOnceSeen[key] = true
	return true // New element
}

// SetSiteHost sets the site host for external link detection.
func (e *CandidateElementExtractor) SetSiteHost(host string) {
	e.siteHost = strings.ToLower(host)
}

// SetFormHandler sets the form handler for form-to-element linking.
func (e *CandidateElementExtractor) SetFormHandler(handler FormHandler) {
	e.formHandler = handler
}

// Extract extracts candidate elements from the page.
// Uses a shared seen map across all extraction methods for proper deduplication.
// If CrawlFrames is enabled, recursively extracts from iframes.
func (e *CandidateElementExtractor) Extract(ctx context.Context, page *browser.Page) ([]*CandidateElement, error) {
	zap.L().Debug("Starting candidate element extraction",
		zap.Bool("crawl_frames", e.crawlFrames),
		zap.Bool("use_cdp", e.useCDP),
		zap.Bool("randomize", e.randomizeElements),
		zap.Bool("click_once", e.clickOnce))

	if e.checkedElements != nil && !e.checkedElements.CheckCrawlCondition(page) {
		zap.L().Debug("Crawl condition not met, skipping extraction")
		return nil, nil
	}

	// CRITICAL FIX: Single shared seen map for global deduplication across all methods
	seen := make(map[string]bool)

	// Extract from main page and all frames
	candidates := e.extractFromPageAndFrames(ctx, page, seen, "")

	zap.L().Debug("Candidate element extraction completed",
		zap.Int("selectors_count", len(e.clickSelectors)))

	// Randomize element order if enabled)
	if e.randomizeElements && len(candidates) > 1 {
		shuffleCandidates(candidates)
		zap.L().Debug("Candidates randomized")
	}

	return candidates, nil
}

// extractFromPageAndFrames extracts candidate elements from a page and recursively from its frames.
// framePath is the dot-separated path to this frame (e.g., "frame1.frame2").
func (e *CandidateElementExtractor) extractFromPageAndFrames(ctx context.Context, page *browser.Page, seen map[string]bool, framePath string) []*CandidateElement {
	candidates := make([]*CandidateElement, 0)

	// Extract from current page
	pageCandidates := e.extractFromPage(page, seen, framePath)
	candidates = append(candidates, pageCandidates...)

	// Recursively extract from frames if enabled
	if e.crawlFrames {
		frameCandidates := e.extractFromFrames(ctx, page, seen, framePath)
		candidates = append(candidates, frameCandidates...)
	}

	return candidates
}

// extractFromPage extracts candidate elements from a single page (no frame recursion).
// CRITICAL: framePath must be passed to extraction methods so deduplication works correctly.
func (e *CandidateElementExtractor) extractFromPage(page *browser.Page, seen map[string]bool, framePath string) []*CandidateElement {
	candidates := make([]*CandidateElement, 0)

	// Method 1: CSS Selector matching
	// Pass framePath so ClickOnce deduplication works correctly across frames
	selectorCandidates, err := e.extractBySelectors(page, seen, framePath)
	if err == nil {
		candidates = append(candidates, selectorCandidates...)
	}

	// Method 2: CDP Event Listener Detection
	if e.useCDP {
		cdpCandidates, err := e.extractByCDP(page, seen, framePath)
		if err == nil {
			candidates = append(candidates, cdpCandidates...)
		}

		// Method 3: Semantic / delegated-event detection. React/Vue attach one
		// click listener to the document/root, so per-element getEventListeners
		// (Method 2) sees nothing and a clickable <div>/<span> is missed by the CSS
		// selectors too. This shares `seen`, so it only adds what the earlier
		// passes didn't already surface.
		semCandidates, err := e.extractBySemantic(page, seen, framePath)
		if err == nil {
			candidates = append(candidates, semCandidates...)
		}

		// Method 4: Hover-menu triggers whose submenu opens on CSS :hover — the
		// click passes can't reach them (clicking a hover-only trigger does
		// nothing), so their whole submenu of links would be missed. Narrowly
		// targeted and capped in JS so it adds only a handful of hover actions.
		hoverCandidates, err := e.extractHoverMenus(page, seen, framePath)
		if err == nil {
			candidates = append(candidates, hoverCandidates...)
		}
	}

	// and caused duplicate elements with different CSS selectors.

	return candidates
}

// extractFromFrames extracts candidate elements from all iframes in the page.
func (e *CandidateElementExtractor) extractFromFrames(ctx context.Context, page *browser.Page, seen map[string]bool, parentFramePath string) []*CandidateElement {
	candidates := make([]*CandidateElement, 0)

	frameInfos, err := page.FramesWithInfo()
	if err != nil {
		return candidates
	}

	for _, fi := range frameInfos {
		// Generate frame identifier)
		// FramesWithInfo already uses id before name order
		frameID := fi.ID
		if frameID == "" {
			frameID = fmt.Sprintf("frame%d", fi.Index)
		}

		// Build full frame path
		framePath := frameID
		if parentFramePath != "" {
			framePath = parentFramePath + "." + frameID
		}

		if e.shouldIgnoreFrame(framePath) {
			continue
		}

		// Recursively extract from this frame, guarded against go-rod panicking
		// on a frame that went cross-origin/detached mid-crawl (nil
		// ContentDocument in getJSCtxID). The browser wrappers already convert
		// these to errors, but this is a per-frame backstop so a single bad
		// frame can never abort the whole crawl.
		frameCandidates := e.safeExtractFrame(ctx, fi.Page, seen, framePath)
		candidates = append(candidates, frameCandidates...)
	}

	return candidates
}

// safeExtractFrame wraps frame extraction in a panic recovery so a go-rod nil
// dereference on a cross-origin/detached frame is contained to that frame
// instead of crashing the entire scan.
func (e *CandidateElementExtractor) safeExtractFrame(ctx context.Context, page *browser.Page, seen map[string]bool, framePath string) (candidates []*CandidateElement) {
	defer func() {
		if r := recover(); r != nil {
			zap.L().Debug("Recovered from panic during frame extraction (cross-origin/detached frame)",
				zap.String("frame_path", framePath),
				zap.Any("panic", r))
			candidates = nil
		}
	}()
	return e.extractFromPageAndFrames(ctx, page, seen, framePath)
}

// shouldIgnoreFrame checks if a frame should be ignored based on patterns.
// Checks both exact match and wildcard patterns.
func (e *CandidateElementExtractor) shouldIgnoreFrame(frameIdentification string) bool {
	for _, pattern := range e.frameIgnorePatterns {
		if matchesFrameIgnorePattern(pattern, frameIdentification) {
			return true
		}
	}
	return false
}

// matchesFrameIgnorePattern checks if frameIdentification matches the ignore pattern.
func matchesFrameIgnorePattern(pattern, frameIdentification string) bool {
	// Handle both "%" and "*" (Go style) wildcards
	if strings.Contains(pattern, "%") || strings.Contains(pattern, "*") {
		// Convert to regex pattern
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, "\\%", ".*")
		regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")
		matched, _ := regexp.MatchString(regexPattern, frameIdentification)
		return matched
	}
	// Exact match
	return pattern == frameIdentification
}

// shuffleCandidates randomly shuffles the candidate elements slice using crypto/rand.
// Uses Fisher-Yates shuffle algorithm for unbiased randomization.
func shuffleCandidates(candidates []*CandidateElement) {
	n := len(candidates)
	for i := n - 1; i > 0; i-- {
		// Use crypto/rand for proper randomization
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			// Fallback: skip shuffle if random fails
			return
		}
		j := int(jBig.Int64())
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}
}

// extractBySelectors extracts candidate elements using CSS selectors.
func (e *CandidateElementExtractor) extractBySelectors(page *browser.Page, seen map[string]bool, framePath string) ([]*CandidateElement, error) {
	candidates := make([]*CandidateElement, 0)

	for _, selector := range e.clickSelectors {
		elements, err := page.Elements(selector)
		if err != nil {
			continue
		}

		for _, elem := range elements {
			// Check exclusions (with recursive parent check)
			if e.isExcluded(elem) {
				continue
			}

			// evaluateElements() does NOT check visibility/interactability.
			// It extracts ALL elements matching the tag, letting the Crawler handle click failures later.

			// Get XPath for identification (primary key)
			xpath, err := elem.GetXPath()
			if err != nil || xpath == "" {
				continue
			}

			// Deduplicate using shared seen map (per-extraction dedup)
			// CRITICAL: Include framePath in key so same selector in different frames isn't filtered
			seenKey := framePath + ":" + xpath
			if seen[seenKey] {
				continue
			}
			seen[seenKey] = true

			// Check href filtering for links
			href := ""
			if h, _ := elem.Attribute("href"); h != "" && h != "<nil>" {
				if e.shouldSkipHref(h) {
					continue
				}
				href = h
			}

			candidate := e.createCandidateElement(elem, xpath, framePath, href, EventTypeClick)

			if e.markChecked(candidate) {
				candidates = append(candidates, candidate)
				// for each candidate added during extraction.
				if e.checkedElements != nil {
					e.checkedElements.IncreaseElementsCounter()
				}
			}
		}
	}

	// Shadow-DOM pass: web-component apps render their clickables inside shadow
	// roots, which the light-DOM page.Elements above cannot see. Run it ONCE with
	// all click selectors combined (one shadow-tree walk instead of one per
	// selector); ShadowElements tags each match with a stable attribute so it is
	// identified — and later re-resolved — by that selector rather than an XPath
	// that cannot cross a shadow boundary.
	shadowElems, err := page.ShadowElements(strings.Join(e.clickSelectors, ","))
	if err != nil {
		return candidates, nil
	}
	for _, elem := range shadowElems {
		if e.isExcluded(elem) {
			continue
		}
		uid, _ := elem.Attribute(browser.ShadowUIDAttr)
		if uid == "" || uid == "<nil>" {
			continue
		}
		idSelector := browser.ShadowUIDSelector(uid)

		seenKey := framePath + ":shadow:" + uid
		if seen[seenKey] {
			continue
		}
		seen[seenKey] = true

		href := ""
		if h, _ := elem.Attribute("href"); h != "" && h != "<nil>" {
			if e.shouldSkipHref(h) {
				continue
			}
			href = h
		}

		candidate := e.createCandidateElement(elem, idSelector, framePath, href, EventTypeClick)
		candidate.Identification = NewIdentification(HowID, idSelector)

		if e.markChecked(candidate) {
			candidates = append(candidates, candidate)
			if e.checkedElements != nil {
				e.checkedElements.IncreaseElementsCounter()
			}
		}
	}

	return candidates, nil
}

// extractByCDP extracts candidate elements using Chrome DevTools Protocol.
func (e *CandidateElementExtractor) extractByCDP(page *browser.Page, seen map[string]bool, framePath string) ([]*CandidateElement, error) {
	results, err := DetectClickablesCDP(page)
	if err != nil {
		return nil, err
	}
	return e.buildCandidatesFromResults(page, results, seen, framePath, EventTypeClick), nil
}

// delegatedClickableReasons are the semantic-detector reasons worth adding on top
// of the CSS-selector + CDP passes: framework-delegated affordances that a single
// document/root listener (React/Vue) hides from per-element getEventListeners.
// Native a/button/input reasons are intentionally excluded — the CSS-selector pass
// already covers those, so re-adding them would only duplicate work and add noise.
var delegatedClickableReasons = map[string]bool{
	"cursor":      true, // cursor:pointer on a non-native element (clickable card/div)
	"tabindex":    true, // focusable custom control
	"handler":     true, // ng-click / @click / data-click attribute
	"role-button": true, // ARIA button role
}

// extractBySemantic catches delegated-event clickables — elements a framework
// (React/Vue) wires through one listener on the document/root, so per-element CDP
// getEventListeners sees nothing and the CSS-selector pass misses them because
// they are plain <div>/<span>. It uses semantic affordances as the proxy and
// shares the `seen` map, so it only contributes elements the earlier passes did
// not already surface.
func (e *CandidateElementExtractor) extractBySemantic(page *browser.Page, seen map[string]bool, framePath string) ([]*CandidateElement, error) {
	results, err := DetectClickablesSimple(page)
	if err != nil {
		return nil, err
	}
	filtered := results[:0]
	for _, r := range results {
		if delegatedClickableReasons[r.Reason] {
			filtered = append(filtered, r)
		}
	}
	return e.buildCandidatesFromResults(page, filtered, seen, framePath, EventTypeClick), nil
}

// extractHoverMenus generates HOVER actions for high-precision menu-hover
// affordances — nav triggers whose submenu opens on CSS :hover (aria-haspopup,
// role=menu, Bootstrap dropdown toggles, or an element directly wrapping a hidden
// nested menu). Clicking these often does nothing (the menu is hover-only), so the
// click passes miss the whole submenu and every link inside it. Kept deliberately
// narrow (explicit affordances + a hidden-nested-menu heuristic, capped in JS) so
// it adds a handful of actions per page, not a hover for every element.
func (e *CandidateElementExtractor) extractHoverMenus(page *browser.Page, seen map[string]bool, framePath string) ([]*CandidateElement, error) {
	results, err := DetectHoverMenus(page)
	if err != nil {
		return nil, err
	}
	return e.buildCandidatesFromResults(page, results, seen, framePath, EventTypeHover), nil
}

// buildCandidatesFromResults resolves each detected ClickableResult to a live
// element, applies per-extraction dedup / exclusion / href filtering, and builds
// CandidateElements with the given event type. Shared by the CDP-listener,
// semantic/delegated, and hover-menu passes.
func (e *CandidateElementExtractor) buildCandidatesFromResults(page *browser.Page, results []ClickableResult, seen map[string]bool, framePath string, eventType EventType) []*CandidateElement {
	candidates := make([]*CandidateElement, 0)

	for _, result := range results {
		selector := result.Selector
		if selector == "" {
			selector = result.XPath
		}

		if selector == "" {
			continue
		}

		// Try to get element
		var elem *browser.Element
		if result.XPath != "" {
			elem, _ = page.ElementX(result.XPath)
		} else if result.Selector != "" {
			elem, _ = page.Element(result.Selector)
		}

		if elem == nil {
			continue
		}

		// Get XPath for identification
		xpath, err := elem.GetXPath()
		if err != nil || xpath == "" {
			xpath = selector
		}

		// Deduplicate using shared seen map (per-extraction dedup). Click keeps the
		// bare "frame:xpath" key so it stays consistent with the CSS-selector pass
		// (cross-method dedup); a non-click pass (hover) is namespaced so a hover
		// action and a click action on the same element are not collapsed into one.
		seenKey := framePath + ":" + xpath
		if eventType != EventTypeClick {
			seenKey = string(eventType) + ":" + seenKey
		}
		if seen[seenKey] {
			continue
		}

		// Check exclusions (with recursive parent check)
		if e.isExcluded(elem) {
			continue
		}

		// Check href filtering for links
		href := ""
		if h, _ := elem.Attribute("href"); h != "" && h != "<nil>" {
			if e.shouldSkipHref(h) {
				continue
			}
			href = h
		}

		seen[seenKey] = true

		// Create CandidateElement
		candidate := e.createCandidateElement(elem, xpath, framePath, href, eventType)

		if e.markChecked(candidate) {
			candidates = append(candidates, candidate)
			if e.checkedElements != nil {
				e.checkedElements.IncreaseElementsCounter()
			}
		}
	}

	return candidates
}

// createCandidateElement creates a CandidateElement from a browser element with
// the given event type (click for the selector/CDP/semantic passes, hover for the
// hover-menu pass).
func (e *CandidateElementExtractor) createCandidateElement(elem *browser.Element, xpath string, framePath string, href string, eventType EventType) *CandidateElement {
	candidate := &CandidateElement{
		Identification: NewIdentification(HowXPath, xpath),
		RelatedFrame:   framePath,
		FormInputs:     make([]*FormInput, 0),
		EventType:      eventType,
	}

	// Get tag name
	if tag, err := elem.TagName(); err == nil {
		candidate.TagName = strings.ToLower(tag)
	}

	// Get text content
	if text, err := elem.Text(); err == nil {
		// Truncate long text
		if len(text) > 100 {
			text = text[:100] + "..."
		}
		candidate.Text = strings.TrimSpace(text)
	}

	// Set href
	candidate.Href = href

	candidate.Attributes = elem.GetAllAttributes()

	return candidate
}

// isExcluded checks if an element or any of its parents matches exclusion selectors.
// CRITICAL FIX: Implements recursive parent exclusion checking.
func (e *CandidateElementExtractor) isExcluded(elem *browser.Element) bool {
	// Nothing to match against — skip entirely. Without this guard the ancestor
	// walk below still paid an elem.Parent() CDP round-trip per ancestor, all the
	// way to the root, for every extracted element even though the default crawl
	// configures no exclusion selectors at all.
	if len(e.excludeSelectors) == 0 {
		return false
	}

	// Check current element
	for _, excludeSelector := range e.excludeSelectors {
		if elem.Matches(excludeSelector) {
			return true
		}
	}

	// CRITICAL FIX: Check if any parent is excluded (recursive)
	// This prevents clicking on child elements of excluded containers
	parent, err := elem.Parent()
	for err == nil && parent != nil {
		for _, excludeSelector := range e.excludeSelectors {
			if parent.Matches(excludeSelector) {
				return true
			}
		}
		parent, err = parent.Parent()
	}

	return false
}

// shouldSkipHref checks if an href should be skipped based on filtering rules.
// Do NOT skip javascript: or # links - they may have onclick handlers!
func (e *CandidateElementExtractor) shouldSkipHref(href string) bool {
	// Skip mailto: links
	if strings.HasPrefix(href, "mailto:") {
		return true
	}

	// Skip tel: links (additional common filter)
	if strings.HasPrefix(href, "tel:") {
		return true
	}

	// Skip file downloads
	if fileDownloadPattern.MatchString(href) {
		return true
	}

	// Skip external links if not allowed
	if !e.followExternalLinks && e.siteHost != "" {
		if e.isExternalLink(href) {
			return true
		}
	}

	// Elements with these hrefs often have onclick handlers that cause state changes
	return false
}

// isExternalLink checks if a href points to an external site.
func (e *CandidateElementExtractor) isExternalLink(href string) bool {
	// Skip relative URLs - they're internal
	if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") && !strings.HasPrefix(href, "//") {
		return false
	}

	// Parse the href
	parsed, err := url.Parse(href)
	if err != nil {
		return false
	}

	hrefHost := strings.ToLower(parsed.Host)
	if hrefHost == "" {
		return false
	}

	// Check if hosts match (including subdomains)
	if hrefHost == e.siteHost {
		return false
	}

	// Check if href host is a subdomain of site host or vice versa
	if strings.HasSuffix(hrefHost, "."+e.siteHost) {
		return false
	}
	if strings.HasSuffix(e.siteHost, "."+hrefHost) {
		return false
	}

	return true
}

// SetClickSelectors updates the click selectors.
func (e *CandidateElementExtractor) SetClickSelectors(selectors []string) {
	e.clickSelectors = selectors
}

// AddClickSelector adds a click selector.
func (e *CandidateElementExtractor) AddClickSelector(selector string) {
	e.clickSelectors = append(e.clickSelectors, selector)
}

// AddExcludeSelector adds an exclude selector.
func (e *CandidateElementExtractor) AddExcludeSelector(selector string) {
	e.excludeSelectors = append(e.excludeSelectors, selector)
}

// EnableCDP enables or disables CDP detection.
func (e *CandidateElementExtractor) EnableCDP(enabled bool) {
	e.useCDP = enabled
}

// SetCheckedElements sets the ExtractorManager for global element deduplication.
func (e *CandidateElementExtractor) SetCheckedElements(manager ExtractorManager) {
	e.checkedElements = manager
}
