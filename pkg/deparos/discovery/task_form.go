package discovery

import (
	"context"
	"hash/fnv"
	"net/url"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/spider"
)

// FormSubmissionTask processes form submissions extracted from HTML pages.
// One task per source URL, processes ALL form requests from that page.
// Forms are already fully encoded by FormExtractor (GET params in URL, POST body encoded).
//
// Priority 2 - between observed files and JS extracted requests.
type FormSubmissionTask struct {
	sourceURL       *url.URL
	depth           uint16
	cachedHash      uint64
	getFormRequests func() []*spider.FormRequest
}

// FormSubmissionTaskConfig contains configuration for creating a FormSubmissionTask.
type FormSubmissionTaskConfig struct {
	SourceURL       *url.URL
	Depth           uint16
	GetFormRequests func() []*spider.FormRequest
}

// NewFormSubmissionTask creates a new form submission task with cached hash.
func NewFormSubmissionTask(cfg *FormSubmissionTaskConfig) *FormSubmissionTask {
	task := &FormSubmissionTask{
		sourceURL:       cfg.SourceURL,
		depth:           cfg.Depth,
		getFormRequests: cfg.GetFormRequests,
	}
	task.cachedHash = task.computeHash()
	return task
}

// Hash returns the cached hash computed at creation time.
func (t *FormSubmissionTask) Hash() uint64 {
	return t.cachedHash
}

// computeHash computes FNV-1a 64-bit hash for task deduplication.
// Hash is based on form content (action URLs + methods + bodies), not source page.
// This ensures tasks with same forms are deduplicated.
func (t *FormSubmissionTask) computeHash() uint64 {
	h := fnv.New64a()

	// Include priority
	h.Write([]byte{PriorityFormSubmission})
	h.Write([]byte{0})

	// Include task type marker
	h.Write([]byte("form"))
	h.Write([]byte{0})

	// Include hash of all form requests (not source page)
	forms := t.getFormRequests()
	for _, form := range forms {
		if form.URL != nil {
			h.Write([]byte(form.URL.String()))
			h.Write([]byte{0})
			h.Write([]byte(form.Method))
			h.Write([]byte{0})
			h.Write([]byte(form.Body))
			h.Write([]byte{0})
		}
	}

	return h.Sum64()
}

// Priority returns the task's priority level.
func (t *FormSubmissionTask) Priority() uint8 {
	return PriorityFormSubmission
}

// Description returns a human-readable task description.
func (t *FormSubmissionTask) Description() string {
	return "Form submissions (" + t.sourceURL.Path + ")"
}

// FoundByName returns a short identifier for result attribution.
func (t *FormSubmissionTask) FoundByName() string {
	return "form"
}

// PayloadProvider returns nil - this task iterates form requests directly.
func (t *FormSubmissionTask) PayloadProvider() payload.Provider {
	return nil
}

// FullURL returns the source URL.
func (t *FormSubmissionTask) FullURL() []byte {
	return []byte(t.sourceURL.String())
}

// Extension returns empty string - this task doesn't test extensions.
func (t *FormSubmissionTask) Extension() string {
	return ""
}

// Depth returns the discovery depth.
func (t *FormSubmissionTask) Depth() uint16 {
	return t.depth
}

// IsFromSpider returns true - forms are extracted via spider.
func (t *FormSubmissionTask) IsFromSpider() bool {
	return true
}

// SourceURL returns the source URL for coordinator access.
func (t *FormSubmissionTask) SourceURL() *url.URL {
	return t.sourceURL
}

// GetFormRequestsFunc returns the function to get form requests.
func (t *FormSubmissionTask) GetFormRequestsFunc() func() []*spider.FormRequest {
	return t.getFormRequests
}

// Expand iterates through all form requests and emits URLs.
// This is used for standard task expansion pattern, though forms are executed inline.
func (t *FormSubmissionTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
	forms := t.getFormRequests()

	for _, form := range forms {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if form.URL != nil {
			callback(form.URL.String(), t.depth)
		}
	}

	return nil
}

// GenerateAllVariants returns all request variants for coordinator to execute.
// FormRequests are already fully encoded by FormExtractor, so we convert directly.
func (t *FormSubmissionTask) GenerateAllVariants() []RequestVariant {
	forms := t.getFormRequests()
	variants := make([]RequestVariant, 0, len(forms))

	for _, form := range forms {
		if form.URL == nil {
			continue
		}

		variants = append(variants, RequestVariant{
			Method:      form.Method,
			URL:         form.URL.String(),
			Body:        form.Body,
			ContentType: form.ContentType,
		})
	}

	return variants
}
