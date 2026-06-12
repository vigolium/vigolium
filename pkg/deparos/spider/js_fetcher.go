package spider

import (
	"net/url"
	"strings"
)

// cdnDomains contains CDN domains that host third-party libraries.
// JS files from these domains are skipped as they don't contain useful paths.
var cdnDomains = []string{
	// Major CDNs
	"cdn.jsdelivr.net",
	"fastly.jsdelivr.net",
	"cdnjs.cloudflare.com",
	"unpkg.com",
	"npmcdn.com",
	"esm.sh",
	"esm.run",
	"skypack.dev",
	"jspm.dev",
	"ga.jspm.io",

	// Google
	"ajax.googleapis.com",
	"fonts.googleapis.com",
	"fonts.gstatic.com",
	"www.googletagmanager.com",

	// Microsoft
	"ajax.aspnetcdn.com",

	// jQuery/Bootstrap
	"code.jquery.com",
	"stackpath.bootstrapcdn.com",
	"maxcdn.bootstrapcdn.com",
	"netdna.bootstrapcdn.com",

	// Chinese CDNs
	"cdn.bootcdn.net",
	"cdn.bootcss.com",
	"lib.baomitu.com",
	"cdn.staticfile.org",
	"lf1-cdn-tos.bytegoofy.com",
	"lf3-cdn-tos.bytescm.com",
	"lf6-cdn-tos.bytecdntp.com",
	"s1.hdslb.com",
	"s2.hdslb.com",

	// Font Awesome
	"use.fontawesome.com",
	"kit.fontawesome.com",
	"ka-f.fontawesome.com",

	// Other popular CDNs
	"cdn.tailwindcss.com",
	"cdn.polyfill.io",
	"polyfill.io",
	"cdn.rawgit.com",
	"rawcdn.githack.com",
	"cdn.statically.io",
	"cdn.skypack.dev",
	"yastatic.net",
	"yandex.st",
	"cdnjs.com",
	"raw.githubusercontent.com",
}

// libraryPatterns contains filename patterns for pure UI/visual third-party libraries.
// These are skipped because they contain NO application-specific endpoints or paths.
//
// INTENTIONALLY NOT BLOCKED (may contain API endpoints/routes):
// - HTTP clients (axios, fetch, superagent) - may define API endpoints
// - Routers (vue-router, react-router) - contain application routes
// - State management (redux, mobx, zustand) - may have API configurations
// - WebSocket clients (socket.io, signalr) - may have endpoint URLs
// - Major frameworks (react, vue, angular) - avoid blocking app bundles like "app.react.js"
var libraryPatterns = []string{
	// Core UI frameworks (specific patterns to avoid false positives)
	"jquery.min",
	"jquery.slim",
	"jquery-ui",
	"jquery-migrate",
	"bootstrap.min",
	"bootstrap.bundle",
	"bootstrap-datepicker",
	"jquery",

	// Polyfills (browser compatibility only, no app logic)
	"polyfill.min",
	"core-js.min",
	"core-js-bundle",
	"regenerator-runtime",
	"es5-shim",
	"es6-shim",
	"html5shiv",
	"respond.min",
	"modernizr",

	// Animation/Motion libraries (pure visual effects)
	"gsap.min",
	"gsap-",
	"anime.min",
	"animejs",
	"lottie.min",
	"lottie-web",
	"lottie-player",
	"framer-motion",
	"popmotion",
	"velocity.min",
	"velocity.ui",
	"scrollreveal",
	"scrollmagic",
	"locomotive-scroll",
	"aos.js",
	"rellax.min",
	"parallax.min",
	"skrollr.min",

	// Charts/Visualization (pure rendering, no app endpoints)
	"d3.min",
	"d3.v",
	"chart.min",
	"chart.js",
	"chartjs",
	"highcharts",
	"echarts.min",
	"apexcharts",
	"plotly.min",
	"plotly-",
	"c3.min",
	"nvd3.min",

	// 3D/Games (pure rendering engines)
	"three.min",
	"three.module",
	"babylon.min",
	"babylonjs",
	"pixi.min",
	"pixijs",
	"phaser.min",

	// Icons (pure visual assets)
	"fontawesome",
	"fa-solid",
	"fa-regular",
	"fa-brands",
	"feather-icons",
	"lucide.min",
	"heroicons",

	// UI widgets (pure visual components)
	"swiper.min",
	"swiper-bundle",
	"slick.min",
	"owl.carousel",
	"glide.min",
	"flickity",
	"splide.min",
	"lightbox.min",
	"fancybox",
	"magnific-popup",
	"photoswipe",
	"sweetalert",
	"toastr.min",
	"notyf.min",
	"tippy.min",
	"popper.min",
	"tooltip.min",

	// Date/Time display (formatting only)
	"moment.min",
	"moment-with-locales",
	"dayjs.min",
	"luxon.min",
	"date-fns.min",

	// Code editors (UI rendering only)
	"prism.min",
	"prism.js",
	"highlight.min",
	"codemirror.min",
	"ace.min",
	"ace-builds",
	"monaco-editor",

	// Rich text editors (UI only)
	"tinymce.min",
	"ckeditor",
	"quill.min",
	"summernote",
	"froala",

	// Media players (UI rendering only)
	"video.min",
	"video.js",
	"videojs",
	"plyr.min",
	"mediaelement",
	"jwplayer",
	"howler.min",
	"wavesurfer.min",

	// Maps (rendering only, not map data APIs)
	"leaflet.min",
	"leaflet.js",
	"openlayers.min",
	"mapbox-gl",

	// Analytics/Tracking (third-party services)
	"gtag.js",
	"gtm.js",
	"google-analytics",
	"googletagmanager",
	"hotjar",
	"mixpanel.min",
	"fullstory",
	"mouseflow",
	"crazyegg",
	"optimizely",

	// Social widgets (third-party)
	"twitter-widget",
	"facebook-sdk",
	"platform.twitter",
	"connect.facebook",
	"sharethis",
	"addthis",

	// Chat widgets (third-party services)
	"intercom.min",
	"drift.min",
	"crisp.chat",
	"tawk.to",
	"zendesk",
	"freshchat",
	"livechat",
	"olark",

	// CAPTCHA (third-party services)
	"recaptcha",
	"hcaptcha",
	"turnstile",

	// Payment SDKs (third-party, use specific patterns)
	"stripe.min",
	"paypal.min",
	"paypalobjects",
	"braintree.min",

	// Transpiler runtime (generated code, no app logic)
	"tslib.min",
	"tslib.es",
}

// isCDNDomain checks if the URL host is a known CDN domain.
func isCDNDomain(host string) bool {
	host = strings.ToLower(host)
	for _, cdn := range cdnDomains {
		if host == cdn || strings.HasSuffix(host, "."+cdn) {
			return true
		}
	}
	return false
}

// isLibraryFile checks if the URL path matches a known library pattern.
func isLibraryFile(urlPath string) bool {
	// Get filename from path
	lastSlash := strings.LastIndex(urlPath, "/")
	filename := urlPath
	if lastSlash >= 0 && lastSlash < len(urlPath)-1 {
		filename = urlPath[lastSlash+1:]
	}

	filenameLower := strings.ToLower(filename)
	for _, pattern := range libraryPatterns {
		if strings.Contains(filenameLower, pattern) {
			return true
		}
	}
	return false
}

// ShouldSkipJSPathExtraction checks if a JS URL should skip path extraction.
// Returns true for CDN domains and known library files that don't contain
// application-specific endpoints. The JS file will still be recorded as a finding,
// but path extraction will be skipped.
func ShouldSkipJSPathExtraction(jsURL *url.URL) bool {
	return isCDNDomain(jsURL.Host) || isLibraryFile(jsURL.Path)
}
