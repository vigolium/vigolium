package spider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsCDNDomain(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		// Exact matches
		{
			name:     "cdn.jsdelivr.net exact",
			host:     "cdn.jsdelivr.net",
			expected: true,
		},
		{
			name:     "cdnjs.cloudflare.com exact",
			host:     "cdnjs.cloudflare.com",
			expected: true,
		},
		{
			name:     "unpkg.com exact",
			host:     "unpkg.com",
			expected: true,
		},
		{
			name:     "ajax.googleapis.com exact",
			host:     "ajax.googleapis.com",
			expected: true,
		},
		{
			name:     "code.jquery.com exact",
			host:     "code.jquery.com",
			expected: true,
		},
		{
			name:     "stackpath.bootstrapcdn.com exact",
			host:     "stackpath.bootstrapcdn.com",
			expected: true,
		},
		{
			name:     "fonts.googleapis.com exact",
			host:     "fonts.googleapis.com",
			expected: true,
		},

		// Subdomain of CDN
		{
			name:     "subdomain of cdn.jsdelivr.net",
			host:     "fastly.cdn.jsdelivr.net",
			expected: true,
		},

		// Case insensitive
		{
			name:     "uppercase CDN domain",
			host:     "CDN.JSDELIVR.NET",
			expected: true,
		},
		{
			name:     "mixed case CDN domain",
			host:     "Cdn.JsDelivr.Net",
			expected: true,
		},

		// Not CDN
		{
			name:     "normal domain",
			host:     "example.com",
			expected: false,
		},
		{
			name:     "api subdomain",
			host:     "api.example.com",
			expected: false,
		},
		{
			name:     "similar but not CDN",
			host:     "notjsdelivr.net",
			expected: false,
		},
		{
			name:     "target domain",
			host:     "www.target.com",
			expected: false,
		},
		{
			name:     "empty host",
			host:     "",
			expected: false,
		},

		// Chinese CDNs
		{
			name:     "cdn.bootcdn.net",
			host:     "cdn.bootcdn.net",
			expected: true,
		},
		{
			name:     "lib.baomitu.com",
			host:     "lib.baomitu.com",
			expected: true,
		},

		// Font Awesome
		{
			name:     "use.fontawesome.com",
			host:     "use.fontawesome.com",
			expected: true,
		},
		{
			name:     "kit.fontawesome.com",
			host:     "kit.fontawesome.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCDNDomain(tt.host)
			assert.Equal(t, tt.expected, result, "host: %s", tt.host)
		})
	}
}

func TestIsLibraryFile(t *testing.T) {
	tests := []struct {
		name     string
		urlPath  string
		expected bool
	}{
		// jQuery - block specific library patterns
		{
			name:     "jquery.min.js",
			urlPath:  "/js/jquery.min.js",
			expected: true,
		},
		{
			name:     "jquery-3.6.0.min.js",
			urlPath:  "/assets/jquery-3.6.0.min.js",
			expected: true,
		},
		{
			name:     "jquery.slim.min.js",
			urlPath:  "/vendor/jquery.slim.min.js",
			expected: true,
		},

		// Bootstrap - block specific patterns
		{
			name:     "bootstrap.min.js",
			urlPath:  "/js/bootstrap.min.js",
			expected: true,
		},
		{
			name:     "bootstrap.bundle.min.js",
			urlPath:  "/assets/bootstrap.bundle.min.js",
			expected: true,
		},

		// Frameworks - NOT blocked (may contain app routes/endpoints)
		{
			name:     "angular.min.js - not blocked, may be app bundle",
			urlPath:  "/libs/angular.min.js",
			expected: false,
		},
		{
			name:     "react.production.min.js - not blocked, may be app bundle",
			urlPath:  "/node_modules/react/react.production.min.js",
			expected: false,
		},
		{
			name:     "react-dom.production.min.js - not blocked",
			urlPath:  "/static/react-dom.production.min.js",
			expected: false,
		},
		{
			name:     "vue.min.js - not blocked, may be app bundle",
			urlPath:  "/js/vue.min.js",
			expected: false,
		},
		{
			name:     "vue.runtime.esm.js - not blocked",
			urlPath:  "/assets/vue.runtime.esm.js",
			expected: false,
		},

		// Utility/HTTP libraries - NOT blocked (may contain API endpoints)
		{
			name:     "lodash.min.js - not blocked",
			urlPath:  "/vendor/lodash.min.js",
			expected: false,
		},
		{
			name:     "moment.min.js - blocked (date formatting only)",
			urlPath:  "/js/moment.min.js",
			expected: true,
		},
		{
			name:     "axios.min.js - not blocked (may contain API endpoints)",
			urlPath:  "/lib/axios.min.js",
			expected: false,
		},

		// Bundle patterns - NOT blocked (too generic, may be app bundles)
		{
			name:     "vendor.js - not blocked, may contain app code",
			urlPath:  "/static/js/vendor.js",
			expected: false,
		},
		{
			name:     "vendors.chunk.js - not blocked",
			urlPath:  "/static/js/vendors.chunk.js",
			expected: false,
		},
		{
			name:     "chunk-vendors.js - not blocked",
			urlPath:  "/js/chunk-vendors.js",
			expected: false,
		},
		{
			name:     "runtime.js - not blocked, may contain app code",
			urlPath:  "/dist/runtime.js",
			expected: false,
		},
		{
			name:     "polyfills.js - not blocked (generic pattern)",
			urlPath:  "/static/polyfills.js",
			expected: false,
		},
		{
			name:     "polyfill.min.js - blocked (specific polyfill pattern)",
			urlPath:  "/static/polyfill.min.js",
			expected: true,
		},

		// Generic min patterns - NOT blocked (too generic)
		{
			name:     "something.min.js - not blocked, too generic",
			urlPath:  "/js/something.min.js",
			expected: false,
		},
		{
			name:     "library.prod.js - not blocked, too generic",
			urlPath:  "/dist/library.prod.js",
			expected: false,
		},

		// Charts - blocked (pure visualization)
		{
			name:     "chart.min.js",
			urlPath:  "/vendor/chart.min.js",
			expected: true,
		},
		{
			name:     "highcharts.js",
			urlPath:  "/lib/highcharts.js",
			expected: true,
		},
		{
			name:     "d3.v7.min.js",
			urlPath:  "/assets/d3.v7.min.js",
			expected: true,
		},

		// Analytics - block specific third-party patterns
		{
			name:     "gtag.js - blocked (Google tracking)",
			urlPath:  "/scripts/gtag.js",
			expected: true,
		},
		{
			name:     "analytics.js - not blocked (may be app analytics)",
			urlPath:  "/js/analytics.js",
			expected: false,
		},
		{
			name:     "hotjar.js - blocked (third-party)",
			urlPath:  "/tracking/hotjar.js",
			expected: true,
		},

		// Payment - block specific SDK patterns
		{
			name:     "stripe.js - not blocked (generic, may be app code)",
			urlPath:  "/payment/stripe.js",
			expected: false,
		},
		{
			name:     "stripe.min.js - blocked (specific SDK)",
			urlPath:  "/payment/stripe.min.js",
			expected: true,
		},

		// Animation libraries - blocked (pure visual)
		{
			name:     "gsap.min.js - blocked (animation library)",
			urlPath:  "/js/gsap.min.js",
			expected: true,
		},
		{
			name:     "lottie-web.js - blocked (animation library)",
			urlPath:  "/lib/lottie-web.js",
			expected: true,
		},
		{
			name:     "framer-motion.js - blocked (animation library)",
			urlPath:  "/dist/framer-motion.js",
			expected: true,
		},

		// Case insensitive
		{
			name:     "JQUERY.MIN.JS uppercase",
			urlPath:  "/JS/JQUERY.MIN.JS",
			expected: true,
		},

		// Should NOT match (target-specific files)
		{
			name:     "app-specific.js",
			urlPath:  "/js/app-specific.js",
			expected: false,
		},
		{
			name:     "custom-api.js",
			urlPath:  "/assets/custom-api.js",
			expected: false,
		},
		{
			name:     "user-dashboard.js",
			urlPath:  "/scripts/user-dashboard.js",
			expected: false,
		},
		{
			name:     "admin-panel.js",
			urlPath:  "/admin/admin-panel.js",
			expected: false,
		},
		{
			name:     "checkout-flow.js",
			urlPath:  "/checkout/checkout-flow.js",
			expected: false,
		},
		{
			name:     "api-client.js",
			urlPath:  "/lib/api-client.js",
			expected: false,
		},
		{
			name:     "config.js",
			urlPath:  "/js/config.js",
			expected: false,
		},
		{
			name:     "routes.js",
			urlPath:  "/app/routes.js",
			expected: false,
		},
		{
			name:     "services.js",
			urlPath:  "/src/services.js",
			expected: false,
		},
		{
			name:     "controllers.js",
			urlPath:  "/app/controllers.js",
			expected: false,
		},
		{
			name:     "empty path",
			urlPath:  "",
			expected: false,
		},
		{
			name:     "just slash",
			urlPath:  "/",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLibraryFile(tt.urlPath)
			assert.Equal(t, tt.expected, result, "path: %s", tt.urlPath)
		})
	}
}

func BenchmarkIsCDNDomain(b *testing.B) {
	hosts := []string{
		"cdn.jsdelivr.net",
		"example.com",
		"api.target.com",
		"cdnjs.cloudflare.com",
		"www.mysite.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isCDNDomain(hosts[i%len(hosts)])
	}
}

func BenchmarkIsLibraryFile(b *testing.B) {
	paths := []string{
		"/js/jquery.min.js",
		"/app/custom-code.js",
		"/vendor/bootstrap.bundle.min.js",
		"/src/api-client.js",
		"/static/js/vendor.js",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isLibraryFile(paths[i%len(paths)])
	}
}
