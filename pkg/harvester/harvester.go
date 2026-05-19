package harvester

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/sourcegraph/conc"
	"go.uber.org/zap"
)

// Harvester orchestrates multiple sources to collect URLs for target domains.
type Harvester struct {
	sources []Source
	timeout time.Duration
}

// New creates a new Harvester with the given sources and timeout.
func New(sources []Source, timeout time.Duration) *Harvester {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &Harvester{
		sources: sources,
		timeout: timeout,
	}
}

// Harvest collects URLs from all sources for the given domains.
// Results are deduplicated and streamed to the returned channel.
// The channel is closed when all sources have finished or the timeout expires.
func (h *Harvester) Harvest(ctx context.Context, domains []string) <-chan string {
	out := make(chan string, 100)

	go func() {
		defer close(out)

		ctx, cancel := context.WithTimeout(ctx, h.timeout)
		defer cancel()

		// Merge results from all sources across all domains
		merged := make(chan Result, 100)
		var wg conc.WaitGroup

		for _, src := range h.sources {
			for _, domain := range domains {
				s, d := src, domain
				wg.Go(func() {
					ch := s.Run(ctx, d)
					for r := range ch {
						select {
						case <-ctx.Done():
							return
						case merged <- r:
						}
					}
				})
			}
		}

		// Close merged channel when all sources are done
		go func() {
			defer close(merged)
			wg.Wait()
		}()

		// Deduplicate and emit URLs
		seen := make(map[string]struct{})
		var total, errors int

		for r := range merged {
			if r.Error != nil {
				errors++
				zap.L().Debug("Harvester source error",
					zap.String("source", r.Source),
					zap.Error(r.Error))
				continue
			}

			normalized := normalizeURL(r.URL)
			if normalized == "" {
				continue
			}

			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			total++

			select {
			case <-ctx.Done():
				return
			case out <- r.URL:
			}
		}

		zap.L().Info("Harvester completed",
			zap.Int("unique_urls", total),
			zap.Int("errors", errors),
			zap.Int("sources", len(h.sources)),
			zap.Int("domains", len(domains)))
	}()

	return out
}

// normalizeURL strips fragments and validates that a URL has a scheme and host.
// Returns empty string for invalid URLs.
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	if u.Scheme == "" || u.Host == "" {
		return ""
	}

	// Strip fragment
	u.Fragment = ""
	return u.String()
}
