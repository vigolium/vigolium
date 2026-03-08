package discovery

import (
	"net/http"
	"net/url"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
)

// Result represents a complete discovery result.
// The ResponseChain (rc) is transient and only valid during callback execution.
// Body is copied at persist time in onResult(), not in coordinator.
type Result struct {
	URL      *url.URL
	Request  *storage.RequestData
	Metadata *storage.DiscoveryMetadata

	// rc is transient - valid only until Close() is called by the coordinator.
	// Use accessor methods (StatusCode, BodyBytes, Response) for safe access.
	rc *responsechain.ResponseChain
}

// StatusCode returns the HTTP status code from the response.
// Returns 0 if ResponseChain is not available.
func (r *Result) StatusCode() int {
	if r.rc == nil || !r.rc.Has() {
		return 0
	}
	return r.rc.Response().StatusCode
}

// BodyBytes returns the response body bytes.
// Returns nil if ResponseChain is not available.
// WARNING: The returned slice is only valid until Close() is called on the ResponseChain.
func (r *Result) BodyBytes() []byte {
	if r.rc == nil || !r.rc.Has() {
		return nil
	}
	return r.rc.BodyBytes()
}

// Response returns the underlying http.Response.
// Returns nil if ResponseChain is not available.
func (r *Result) Response() *http.Response {
	if r.rc == nil || !r.rc.Has() {
		return nil
	}
	return r.rc.Response()
}

// ResponseChain returns the underlying ResponseChain for direct access.
// Returns nil if not available.
// WARNING: Only valid during callback execution - do not retain reference.
func (r *Result) ResponseChain() *responsechain.ResponseChain {
	return r.rc
}
