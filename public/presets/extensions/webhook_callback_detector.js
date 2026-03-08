// webhook_callback_detector.js
// Passive module: Detects webhook and callback URLs in JSON response bodies.
// These endpoints may be vulnerable to SSRF if an attacker can control the
// callback destination.

var CALLBACK_KEYS_REGEX = "\"(?:callback_url|webhook|webhook_url|notify_url|postback_url|hook_url)\"\\s*:\\s*\"(https?://[^\"]+)\"";

module.exports = {
  id: "webhook-callback-detector",
  name: "Webhook/Callback URL Detector",
  description: "Detects webhook and callback URLs in JSON responses that may be vulnerable to SSRF",
  type: "passive",
  severity: "suspect",
  confidence: "tentative",
  scope: "response",
  tags: ["ssrf", "webhook", "api", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.body) return null;

    var contentType = ctx.response.headers ? ctx.response.headers["content-type"] || "" : "";
    if (contentType.toLowerCase().indexOf("json") === -1) return null;

    var body = ctx.response.body;
    var extracted = vigolium.utils.regexExtract(body, CALLBACK_KEYS_REGEX);
    if (!extracted || extracted.length === 0) return null;

    // Deduplicate URLs
    var seen = {};
    var urls = [];
    for (var i = 0; i < extracted.length; i++) {
      var url = extracted[i];
      if (!seen[url]) {
        seen[url] = true;
        urls.push(url);
      }
    }

    var remarkTags = ["webhook-callback"];

    // Check if any URLs point to external domains
    var requestHost = "";
    if (ctx.request && ctx.request.url) {
      var parsed = vigolium.parse.url(ctx.request.url);
      if (parsed) requestHost = parsed.hostname;
    }

    var externalUrls = [];
    for (var j = 0; j < urls.length; j++) {
      var callbackParsed = vigolium.parse.url(urls[j]);
      if (callbackParsed && callbackParsed.hostname !== requestHost) {
        externalUrls.push(urls[j]);
      }
    }

    if (externalUrls.length > 0) {
      remarkTags.push("webhook-callback:external");
    }

    if (ctx.record && ctx.record.uuid) {
      ctx.record.addRemarks(remarkTags);
    }

    var description = "JSON response contains webhook/callback URLs:\n" +
      urls.map(function(u) { return "- `" + u + "`"; }).join("\n");

    if (externalUrls.length > 0) {
      description += "\n\n**External callback URLs detected** — these may be controllable for SSRF.";
    }

    return [{
      url: ctx.request ? ctx.request.url : "",
      matched: urls.join(", "),
      name: "Webhook/Callback URL in Response",
      description: description,
      severity: "suspect"
    }];
  }
};
