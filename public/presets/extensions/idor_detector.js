// idor_detector.js
// Active module: IDOR/BOLA (Insecure Direct Object Reference / Broken Object Level Auth) detector.
//
// Strategy:
//   For each scanned request whose URL contains a dynamic path segment (numeric ID, UUID, etc.),
//   query the database for related records on the same endpoint with different IDs. Then compare
//   their responses. If some responses diverge significantly from the majority — e.g. one returns
//   full data while others return 403 — that inconsistency signals a potential IDOR vulnerability.
//
// Optionally, when vigolium.agent is configured, an LLM confirmation step reduces false positives
// before a finding is reported.
//
// Requires: vigolium.db (repository must be configured).
// Optional: vigolium.agent (LLM client configured in vigolium-configs.yaml).

module.exports = {
  id: "idor-detector",
  name: "IDOR/BOLA Detector",
  description: "Detects broken object-level authorization by comparing responses across related endpoints",
  type: "active",
  severity: "high",
  confidence: "tentative",
  tags: ["idor", "bola", "authz", "api"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    // Require the database API
    if (typeof vigolium.db === "undefined") return null;

    var url = ctx.request.url;
    if (!url) return null;

    // Parse URL components
    var parsed = vigolium.parse.url(url);
    if (!parsed) return null;

    var hostname = parsed.hostname;
    var path = parsed.path;

    // Only proceed if the path contains a dynamic segment
    if (!vigolium.utils.hasDynamicSegment(path)) return null;

    // Derive a path template with wildcard for the dynamic segment(s)
    var template = vigolium.utils.pathToTemplate(path);

    // Query related records: same hostname, same path template
    var related = vigolium.db.records.query({
      hostname: hostname,
      path: template,  // QueryBuilder converts * to % for LIKE
      limit: 15
    });

    if (related.length < 2) {
      // Not enough variation to compare
      return null;
    }

    // Compare responses for anomalies
    var comparison = vigolium.db.compareResponses(related);

    if (comparison.all_similar) {
      // All responses identical — consistent access control, no IDOR signal
      return null;
    }

    if (comparison.variant_count === 0) {
      return null;
    }

    var description = "Responses for endpoint '" + template + "' on " + hostname +
      " vary significantly across different resource IDs. " + comparison.summary +
      "\n\nThis may indicate inconsistent access control (IDOR/BOLA): " +
      "some IDs are accessible while others return authorization errors, " +
      "or different IDs return different data that should be protected.";

    // Optional LLM confirmation to reduce false positives
    if (typeof vigolium.agent !== "undefined" && comparison.variant_count > 0) {
      var divergentUUID = comparison.scores[0].uuid;
      var divergentRecord = vigolium.db.records.get(divergentUUID);
      var similarRecord = null;
      for (var i = 1; i < comparison.scores.length; i++) {
        if (comparison.scores[i].score === 0) {
          similarRecord = vigolium.db.records.get(comparison.scores[i].uuid);
          break;
        }
      }

      if (divergentRecord && similarRecord) {
        var confirmed;
        try {
          confirmed = vigolium.agent.confirmFinding({
            name: "IDOR/BOLA Vulnerability",
            request: ctx.request.raw || url,
            response: divergentRecord.response_body || "",
            matched: comparison.summary,
            baseline_response: similarRecord.response_body || ""
          });
        } catch (e) {
          vigolium.log.warn("idor-detector: agent confirmation failed: " + e);
          confirmed = null;
        }

        if (confirmed !== null) {
          if (!confirmed.confirmed) return null;
          if (confirmed.confidence === "low") return null;
        }
      }
    }

    // Severity based on how many records diverge
    var severity = comparison.variant_count >= 2 ? "high" : "medium";

    return [{
      url: url,
      matched: comparison.summary,
      name: "Potential IDOR/BOLA: " + template,
      description: description,
      severity: severity
    }];
  }
};
