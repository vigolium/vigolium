package http

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
)

// RequestError represents an error that occurred during HTTP request execution.
type RequestError struct {
	// URL is the target URL that failed
	URL string

	// Attempt is the retry attempt number (1-indexed)
	Attempt int

	// Err is the underlying error
	Err error
}

// Error implements the error interface.
func (e *RequestError) Error() string {
	if e.Attempt > 0 {
		return fmt.Sprintf("http request failed (attempt %d) for %s: %v", e.Attempt, e.URL, e.Err)
	}
	return fmt.Sprintf("http request failed for %s: %v", e.URL, e.Err)
}

// Unwrap returns the underlying error for error inspection.
func (e *RequestError) Unwrap() error {
	return e.Err
}

// IsRetryable determines if an error should trigger a retry.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Unwrap RequestError to get underlying error
	var reqErr *RequestError
	if errors.As(err, &reqErr) {
		err = reqErr.Err
	}

	// Network errors are retryable
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// Connection errors are retryable
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		// Timeout errors are retryable
		var timeoutErr net.Error
		if errors.As(urlErr.Err, &timeoutErr) && timeoutErr.Timeout() {
			return true
		}

		// Connection refused/reset errors
		var opErr *net.OpError
		if errors.As(urlErr.Err, &opErr) {
			var sysErr *syscall.Errno
			if errors.As(opErr.Err, &sysErr) {
				if *sysErr == syscall.ECONNREFUSED || *sysErr == syscall.ECONNRESET {
					return true
				}
			}
		}
	}

	return false
}

// RateLimitError represents a rate limit violation.
type RateLimitError struct {
	Limit int
	Wait  string
}

// Error implements the error interface.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limit exceeded (%d req/s), wait %s", e.Limit, e.Wait)
}
