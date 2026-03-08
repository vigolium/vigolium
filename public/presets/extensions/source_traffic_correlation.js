// source_traffic_correlation.js
// Passive module (per_host): Cross-references source code analysis results with
// observed traffic and existing findings to identify routes with dangerous sinks
// that have been reached by traffic but have no active findings yet.

var DANGEROUS_SINKS_REGEX = "eval|exec|innerHTML|dangerouslySetInnerHTML|\\.query\\(|\\.execute\\(";

module.exports = {
  id: "source-traffic-correlation",
  name: "Source-to-Traffic Correlation",
  description: "Cross-references source code sinks with observed traffic to find untested dangerous routes",
  type: "passive",
  severity: "suspect",
  confidence: "tentative",
  scope: "both",
  tags: ["sast", "correlation", "recon"],
  scanTypes: ["per_host"],

  scanPerHost: function(ctx) {
    if (!ctx.request || !ctx.request.url) return null;
    if (!vigolium.source) return null;

    var parsed = vigolium.parse.url(ctx.request.url);
    if (!parsed || !parsed.hostname) return null;
    var hostname = parsed.hostname;

    // Check if we have source code for this host
    var repos = vigolium.source.getByHostname(hostname);
    if (!repos || repos.length === 0) return null;

    // Search for dangerous sinks in source code
    var sinkFiles = vigolium.source.searchFiles(hostname, DANGEROUS_SINKS_REGEX);
    if (!sinkFiles || sinkFiles.length === 0) return null;

    // Get observed traffic records
    var records = vigolium.db && vigolium.db.records ? vigolium.db.records.query({ hostname: hostname }) : null;
    if (!records || records.length === 0) return null;

    // Get existing findings
    var findings = vigolium.db && vigolium.db.findings ? vigolium.db.findings.query({ hostname: hostname }) : null;

    // Build set of paths with existing findings
    var findingPaths = {};
    if (findings) {
      for (var i = 0; i < findings.length; i++) {
        if (findings[i].url) {
          var fp = vigolium.parse.url(findings[i].url);
          if (fp && fp.path) findingPaths[fp.path] = true;
        }
      }
    }

    // Build set of observed traffic paths
    var trafficPaths = {};
    for (var j = 0; j < records.length; j++) {
      if (records[j].path) {
        trafficPaths[records[j].path] = true;
      }
    }

    // Cross-reference: routes with sinks + traffic but no active findings
    var uncovered = [];
    for (var k = 0; k < sinkFiles.length; k++) {
      var sf = sinkFiles[k];
      // sinkFiles entries have .route and .file properties
      if (sf.route && trafficPaths[sf.route] && !findingPaths[sf.route]) {
        uncovered.push({
          route: sf.route,
          file: sf.file || "unknown",
          sinks: sf.matches || []
        });
      }
    }

    if (uncovered.length === 0) return null;

    var remarkTags = ["source-traffic-correlation"];
    if (ctx.record && ctx.record.uuid) {
      ctx.record.addRemarks(remarkTags);
    }

    var details = uncovered.map(function(u) {
      var sinkStr = u.sinks.length > 0 ? " (sinks: " + u.sinks.slice(0, 3).join(", ") + ")" : "";
      return "- `" + u.route + "` in `" + u.file + "`" + sinkStr;
    });

    var description = "Routes with dangerous code sinks that have observed traffic but no active findings:\n" +
      details.join("\n") +
      "\n\nThese routes should be prioritized for active scanning or manual review.";

    return [{
      url: ctx.request.url,
      matched: uncovered.length + " uncovered routes with sinks",
      name: "Source-to-Traffic Correlation: Uncovered Dangerous Routes",
      description: description,
      severity: "suspect"
    }];
  }
};
