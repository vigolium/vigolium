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

// SetClickOnce enables or disables global element deduplication.
// across all states during the entire crawl.
func (e *CandidateElementExtractor) SetClickOnce(enabled bool) {
	e.clickOnceMutex.Lock()
	defer e.clickOnceMutex.Unlock()
	e.clickOnce = enabled
}

// markChecked checks if an element was already extracted and marks it as checked.
// Returns true if the element is NEW (should be extracted), false if already seen.
func (e *CandidateElementExtractor) markChecked(candidate *CandidateElement) bool {
	if !e.clickOnce {
		return true // Always extract when clickOnce is disabled
	}

	e.clickOnceMutex.Lock()
	defer e.clickOnceMutex.Unlock()

	// Use GetUniqueString for state-independent element identification
	uniqueString := candidate.GetUniqueString()
	if e.clickOnceSeen[uniqueString] {
		return false // Already extracted
	}
	e.clickOnceSeen[uniqueString] = true
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

		// Recursively extract from this frame
		frameCandidates := e.extractFromPageAndFrames(ctx, fi.Page, seen, framePath)
		candidates = append(candidates, frameCandidates...)
	}

	return candidates
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

			candidate := e.createCandidateElement(elem, xpath, framePath, href)

			if e.markChecked(candidate) {
				candidates = append(candidates, candidate)
				// for each candidate added during extraction.
				if e.checkedElements != nil {
					e.checkedElements.IncreaseElementsCounter()
				}
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

		// Deduplicate using shared seen map (per-extraction dedup)
		seenKey := framePath + ":" + xpath
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
		candidate := e.createCandidateElement(elem, xpath, framePath, href)

		if e.markChecked(candidate) {
			candidates = append(candidates, candidate)
			if e.checkedElements != nil {
				e.checkedElements.IncreaseElementsCounter()
			}
		}
	}

	return candidates, nil
}

// createCandidateElement creates a CandidateElement from a browser element.
func (e *CandidateElementExtractor) createCandidateElement(elem *browser.Element, xpath string, framePath string, href string) *CandidateElement {
	candidate := &CandidateElement{
		Identification: NewIdentification(HowXPath, xpath),
		RelatedFrame:   framePath,
		FormInputs:     make([]*FormInput, 0),
		EventType:      EventTypeClick, // Default event type
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
