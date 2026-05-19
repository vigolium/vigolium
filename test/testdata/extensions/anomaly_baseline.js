// anomaly_baseline.js — Passive module using vigolium.utils.detectAnomaly()
// Demonstrates anomaly detection on synthetic data built from the current response.
// Compares the current response against synthetic variations to see if it's anomalous.

module.exports = {
  id: "anomaly-baseline",
  name: "Response Anomaly Baseline",
  type: "passive",
  severity: "info",
  description: "Compares current response against typical baselines using anomaly detection",
  scope: "response",
  tags: ["anomaly", "baseline", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.body) return null;

    // Build a set of "baseline" responses: 4 identical + 1 actual
    var baseline = {status: 200, body: "OK", headers: {"content-type": "text/html"}};
    var responses = [
      baseline, baseline, baseline, baseline,
      {status: ctx.response.status, body: ctx.response.body, headers: ctx.response.headers}
    ];

    var ranked = vigolium.utils.detectAnomaly(responses);
    if (!ranked || ranked.length === 0) return null;

    // Check if the actual response (index 4) scored high
    for (var i = 0; i < ranked.length; i++) {
      if (ranked[i].index === 4 && ranked[i].score > 3000) {
        return [{
          url: ctx.request.url,
          matched: "anomaly_score:" + ranked[i].score,
          name: "Response deviates from baseline",
          description: "Anomaly score " + ranked[i].score + " — response differs significantly from a standard 200 OK baseline",
          severity: "info"
        }];
      }
    }
    return null;
  }
};
