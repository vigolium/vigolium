package http

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"

	"github.com/vigolium/vigolium/pkg/requesttransform"
)

// applyRequestTransform runs the process's declared request transform
// (--request-transform, pkg/requesttransform) over a request's FINAL bytes:
// after the default headers, the carried session, the custom headers and the
// live credentials are merged, so a signature over Authorization or a
// timestamp covers what actually leaves. A request no transform matches is
// left exactly as it is.
//
// Only headers, the raw query and the body are written back; the scheme,
// host, port and path are never touched, so the request goes where the scope
// check said it may. A transform that cannot be evaluated (a key the store
// does not hold) fails the request instead of sending it unsigned.
func applyRequestTransform(set *requesttransform.Set, req *retryablehttp.Request) error {
	if set == nil || req == nil || req.Request == nil || req.Request.URL == nil {
		return nil
	}
	u := req.Request.URL
	rawURL := wireURL(u)
	if set.For(rawURL) == nil {
		return nil
	}
	headers := make(map[string]string, len(req.Header))
	for name, values := range req.Header {
		if len(values) > 0 {
			headers[strings.ToLower(name)] = strings.Join(values, ", ")
		}
	}
	if host := req.Host; host != "" {
		headers["host"] = host
	}
	var body *string
	if req.Body != nil {
		raw, err := req.BodyBytes()
		if err != nil {
			return fmt.Errorf("request transform: read body: %w", err)
		}
		if err := req.SetBody(raw); err != nil {
			return fmt.Errorf("request transform: reset body: %w", err)
		}
		s := string(raw)
		body = &s
	}
	out, t, r := set.Apply(requesttransform.Request{Method: req.Method, URL: rawURL, Headers: headers, Body: body})
	if r != nil {
		name := ""
		if t != nil {
			name = t.ID
		}
		return fmt.Errorf("request transform %q refused this request (%s): %s", name, r.Code, r.Detail)
	}
	for name, value := range out.Headers {
		if name == "host" {
			continue
		}
		if prev, ok := headers[name]; ok && prev == value {
			continue
		}
		req.Header.Set(name, value)
	}
	parts := requesttransform.SplitURL(out.URL)
	if parts.Query != u.RawQuery || parts.HasQuery != (u.RawQuery != "" || u.ForceQuery) {
		u.RawQuery = parts.Query
		u.ForceQuery = parts.HasQuery && parts.Query == ""
		// retryablehttp keeps its own parsed copy of the URL; keep it in step.
		if ru := req.URL; ru != nil {
			ru.RawQuery = parts.Query
			params := urlutil.NewOrderedParams()
			params.Decode(parts.Query)
			ru.Params = params
		}
	}
	if out.Body != nil && (body == nil || *out.Body != *body) {
		if err := req.SetBody([]byte(*out.Body)); err != nil {
			return fmt.Errorf("request transform: set body: %w", err)
		}
		req.Header.Del("Content-Length")
	}
	return nil
}

// wireURL is the URL as the request line carries it: scheme, host, the
// escaped path and the raw query.
func wireURL(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	s := u.Scheme + "://" + u.Host + path
	if u.RawQuery != "" || u.ForceQuery {
		s += "?" + u.RawQuery
	}
	return s
}
