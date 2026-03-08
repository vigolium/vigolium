// tag_critical_domains.js
// Post-hook: Upgrades finding severity when the target URL matches a
// critical business domain pattern (e.g. payment, admin, auth).

module.exports = {
  id: "tag-critical-domains",
  name: "Critical Domain Tagger",
  description: "Escalates severity for findings on critical business domains",
  type: "post_hook",
  tags: ["filter", "severity", "post-processing"],

  execute: function(result) {
    if (!result || !result.url) return result;

    var url = result.url.toLowerCase();
    var criticalPatterns = ["payment", "admin", "auth", "checkout", "billing"];

    for (var i = 0; i < criticalPatterns.length; i++) {
      if (url.indexOf(criticalPatterns[i]) !== -1) {
        var currentSeverity = result.info ? result.info.severity : "info";

        // Escalate: info->low, low->medium, medium->high, high->critical
        var escalated = currentSeverity;
        if (currentSeverity === "info") escalated = "low";
        else if (currentSeverity === "low") escalated = "medium";
        else if (currentSeverity === "medium") escalated = "high";
        else if (currentSeverity === "high") escalated = "critical";

        return {
          url: result.url,
          matched: result.matched,
          info: {
            name: result.info.name + " [CRITICAL: " + criticalPatterns[i] + "]",
            description: result.info.description,
            severity: escalated
          }
        };
      }
    }

    return result;
  }
};
