// skip_static_assets.js
// Pre-hook: Drops requests that target static asset paths (images, CSS, JS,
// fonts) so the scanner doesn't waste time fuzzing them.

module.exports = {
  id: "skip-static-assets",
  name: "Static Asset Skipper",
  description: "Skips requests to common static file extensions to reduce scan noise",
  type: "pre_hook",
  tags: ["filter", "performance"],

  execute: function(request) {
    if (!request || !request.url) return request;

    var url = request.url.toLowerCase();

    // Strip query string for extension matching
    var path = url.split("?")[0];

    var staticExts = [
      ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
      ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"
    ];

    for (var i = 0; i < staticExts.length; i++) {
      if (path.indexOf(staticExts[i]) === path.length - staticExts[i].length) {
        return null; // Skip this request
      }
    }

    return request; // Pass through
  }
};
