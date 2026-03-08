package http

import (
	"context"
	nethttp "net/http"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// HTTPClient defines the interface for sending HTTP requests.
// Returns ResponseChain which owns the response data and uses buffer pooling.
// Implementations are provided by the infrastructure layer.
//
// CRITICAL: Caller MUST call ResponseChain.Close() when done to return buffers to pool.
type HTTPClient interface {
	// Send executes an HTTP request and returns a ResponseChain.
	// The ResponseChain owns the response and provides access to headers/body.
	// Caller MUST call Close() on the returned ResponseChain when done.
	Send(ctx context.Context, req *nethttp.Request) (*responsechain.ResponseChain, error)
}
