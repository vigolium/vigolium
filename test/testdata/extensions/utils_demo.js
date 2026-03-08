// utils_demo.js — Demonstrates new vigolium.utils.* and vigolium.scan.* APIs.
// Type: passive (analyzes responses without sending additional requests)

module.exports = {
  id: "utils-demo",
  name: "Utils Demo Extension",
  type: "passive",
  severity: "info",
  confidence: "tentative",
  description: "Demonstrates regex, JSON extraction, scope checking, and module listing",
  scope: "response",
  tags: ["demo", "utils"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    var results = [];
    var body = ctx.response.body || "";

    // Regex: check for email addresses in response
    var hasEmail = vigolium.utils.regexMatch(body, "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    if (hasEmail) {
      var email = vigolium.utils.regexExtract(body, "([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");
      if (email) {
        vigolium.log.info("Found email in response: " + email);
      }
    }

    // JSON extraction: if response is JSON, extract specific fields
    if (body.indexOf("{") === 0) {
      var version = vigolium.utils.jsonExtract(body, "version");
      if (version) {
        vigolium.log.info("API version: " + version);
      }
    }

    // Scope check: verify the current URL is in scope
    var url = ctx.request.url || "";
    if (url) {
      var host = url.split("//")[1];
      if (host) {
        var hostPart = host.split("/")[0];
        var path = "/" + url.split(hostPart)[1];
        var inScope = vigolium.scan.isInScope(hostPart, path);
        vigolium.log.debug("Scope check for " + hostPart + ": " + inScope);
      }
    }

    // List available modules
    var modules = vigolium.scan.listModules();
    vigolium.log.debug("Available modules: " + modules.length);

    // Get current scan info
    var scan = vigolium.scan.getCurrentScan();
    vigolium.log.debug("Scan UUID: " + scan.uuid);

    return results;
  }
};
