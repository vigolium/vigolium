package http

import (
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
// Based on Burp's retry logic in cq5.java.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Unwrap RequestError to get underlying error
	if reqErr, ok := err.(*RequestError); ok {
		err = reqErr.Err
	}

	// Network errors are retryable
	if _, ok := err.(net.Error); ok {
		return true
	}

	// Connection errors are retryable
	if urlErr, ok := err.(*url.Error); ok {
		// Timeout errors are retryable
		if netErr, ok := urlErr.Err.(net.Error); ok && netErr.Timeout() {
			return true
		}

		// Connection refused/reset errors
		if opErr, ok := urlErr.Err.(*net.OpError); ok {
			if sysErr, ok := opErr.Err.(*syscall.Errno); ok {
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
