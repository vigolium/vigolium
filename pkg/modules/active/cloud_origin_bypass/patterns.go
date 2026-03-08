package cloud_origin_bypass

import "regexp"

var cdnHeaders = []string{
	"CF-Ray",
	"X-Cache",
	"X-Amz-Cf-Id",
	"X-Amz-Cf-Pop",
	"X-Served-By",
	"X-CDN",
	"X-Edge-Location",
	"X-Fastly-Request-ID",
}

var cdnViaPatterns = []string{
	"cloudfront",
	"varnish",
	"fastly",
	"akamai",
	"CloudFront",
}

var originURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://[\w.-]+\.s3[.\-][\w.-]*amazonaws\.com[^\s"'<>]*`),
	regexp.MustCompile(`https?://s3[.\-][\w.-]*amazonaws\.com/[\w.-]+[^\s"'<>]*`),
	regexp.MustCompile(`https?://storage\.googleapis\.com/[\w.-]+[^\s"'<>]*`),
	regexp.MustCompile(`https?://[\w.-]+\.storage\.googleapis\.com[^\s"'<>]*`),
	regexp.MustCompile(`https?://[\w.-]+\.blob\.core\.windows\.net[^\s"'<>]*`),
	regexp.MustCompile(`https?://[\w.-]+\.web\.core\.windows\.net[^\s"'<>]*`),
}

var securityHeaders = []string{
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Strict-Transport-Security",
}
