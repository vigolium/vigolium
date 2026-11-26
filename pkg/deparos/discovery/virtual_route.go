package discovery

import (
	"crypto/rand"
	"encoding/hex"
	"mime"
	"net/url"
	"strings"

	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"go.uber.org/zap"
)

// routeAnswer is the part of a response that tells a route apart: its status,
// its media type and, for a redirect, where it points.
type routeAnswer struct {
	status    int
	mediaType string
	location  *url.URL
}

// isPathIndependentRoute reports whether dir is a virtual route rather than a
// directory: the application answers /<random>/<dir path> with the same kind of
// hit, so the route works under any parent. WordPress does this for feed/,
// rss/ and atom/ (/<anything>/feed/ is a 200 feed, /<anything>/rss/ a 301 to
// /<anything>/feed/, /<anything>/feed/atom/ a 200 feed again) and for canonical
// redirects (/<anything>/sample-page/ → /sample-page/). Recursing into such a
// route brute-forces a path that does not exist and finds the same route again
// one level down, without end.
//
// The random segment goes at the root, ahead of the whole path, so a chain of
// rewrites (feed/atom/) is caught at any depth, while a real nested directory
// (/wp-includes/js/) is a miss there.
//
// Only a 2xx or 3xx answer can be ruled virtual. A directory that answers 401
// or 403 is always explored: its listing is refused, yet a concrete file inside
// it may be served. Any failure to probe keeps the directory.
func (e *Engine) isPathIndependentRoute(dir *url.URL) bool {
	if e.httpClient == nil || strings.Trim(dir.Path, "/") == "" {
		return false // the root has no parent to vary
	}
	own, ok := e.answerRoute(dir)
	if !ok || own.status < 200 || own.status >= 400 {
		return false
	}
	token, ok := randomSegment()
	if !ok {
		return false
	}
	path := dir.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	prefix := "/" + token
	probe := *dir
	probe.Path = prefix + path
	probe.RawPath = ""
	probe.RawQuery = ""
	other, ok := e.answerRoute(&probe)
	if !ok {
		return false
	}

	virtual := false
	switch {
	case own.status < 300:
		virtual = other.status >= 200 && other.status < 300 && other.mediaType == own.mediaType
	default:
		virtual = other.status >= 300 && other.status < 400 && sameRedirect(own.location, other.location, prefix)
	}
	if virtual {
		logger.Debug("Directory answers the same under any parent; not recursing into a virtual route",
			zap.String("path", dir.String()),
			zap.String("probe", probe.Path),
			zap.Int("status", own.status))
	}
	return virtual
}

// sameRedirect reports whether two redirects are the same rule: both point to
// one canonical target, or the probe's Location is the directory's own Location
// under the probe's extra prefix (P/rss/ → P/feed/ and /<r>P/rss/ → /<r>P/feed/).
func sameRedirect(own, other *url.URL, prefix string) bool {
	if own == nil || other == nil || own.Host != other.Host || own.RawQuery != other.RawQuery {
		return false
	}
	return own.Path == other.Path || other.Path == prefix+own.Path
}

// answerRoute sends one GET (redirects are not followed by the engine client)
// and reduces the response to a routeAnswer.
func (e *Engine) answerRoute(u *url.URL) (routeAnswer, bool) {
	req, err := pkghttp.NewRequest(u.String()).Headers(e.config.Engine.CustomHeaders).Build()
	if err != nil {
		return routeAnswer{}, false
	}
	rc, err := e.httpClient.Send(e.ctx, req)
	if err != nil {
		return routeAnswer{}, false
	}
	defer rc.Close()
	resp := rc.Response()
	if resp == nil {
		return routeAnswer{}, false
	}
	a := routeAnswer{status: resp.StatusCode}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil {
		a.mediaType = mt
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		if l, err := u.Parse(loc); err == nil {
			a.location = l
		}
	}
	return a, true
}

func randomSegment() (string, bool) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", false
	}
	return "vg" + hex.EncodeToString(b), true
}
