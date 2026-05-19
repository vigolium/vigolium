// sensitive_header_leak.js
// Passive module: Flags responses that expose sensitive server headers
// such as X-Powered-By, Server version strings, or X-AspNet-Version.

module.exports = {
  id: "sensitive-header-leak",
  name: "Sensitive Header Leak",
  description: "Detects responses that expose server technology details through HTTP headers",
  type: "passive",
  severity: "info",
  confidence: "certain",
  scope: "response",
  tags: ["headers", "information-disclosure", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.headers) return null;

    var findings = [];
    var headers = ctx.response.headers;

    // Check for X-Powered-By
    var poweredBy = headers["X-Powered-By"] || headers["x-powered-by"];
    if (poweredBy) {
      findings.push({
        matched: "X-Powered-By: " + poweredBy,
        url: ctx.request.url,
        name: "X-Powered-By header exposed",
        description: "Response includes X-Powered-By: " + poweredBy + " which reveals server technology",
        severity: "info"
      });
    }

    // Check for detailed Server header (with version)
    var server = headers["Server"] || headers["server"];
    if (server && server.match(/[0-9]+\.[0-9]+/)) {
      findings.push({
        matched: "Server: " + server,
        url: ctx.request.url,
        name: "Server version disclosed",
        description: "Response includes Server header with version info: " + server,
        severity: "low"
      });
    }

    // Check for X-AspNet-Version
    var aspnet = headers["X-AspNet-Version"] || headers["x-aspnet-version"];
    if (aspnet) {
      findings.push({
        matched: "X-AspNet-Version: " + aspnet,
        url: ctx.request.url,
        name: "ASP.NET version disclosed",
        description: "Response includes X-AspNet-Version: " + aspnet,
        severity: "info"
      });
    }

    return findings.length > 0 ? findings : null;
  }
};
