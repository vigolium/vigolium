// ai_false_positive_filter.js
// Post-hook: LLM-powered false positive filter.
//
// For every finding that carries request+response data, calls
// vigolium.agent.confirmFinding() to assess whether it is a genuine
// vulnerability. The result is used to:
//   - Drop findings the LLM classifies as false positives (high confidence)
//   - Tag confirmed findings with [AI-verified] and append the reasoning
//   - Tag uncertain findings with [AI-uncertain] and pass them through
//
// Findings without request+response data are always passed through unchanged.
//
// Requires: LLM client configured in the `agent.llm` section of
// vigolium-configs.yaml. Falls back gracefully (pass-through) when unavailable.

module.exports = {
  id: "ai-false-positive-filter",
  type: "post_hook",
  description: "Uses LLM to review findings and drop high-confidence false positives",
  tags: ["ai", "agent", "filter", "post-processing"],

  execute: function(result) {
    // Pass through unchanged if agent API is not configured
    if (typeof vigolium.agent === "undefined") return result;

    // Pass through unchanged if request/response evidence is missing
    if (!result.request || !result.response) return result;

    var confirmation;
    try {
      confirmation = vigolium.agent.confirmFinding({
        name: result.info.name,
        request: result.request,
        response: result.response,
        matched: result.matched || ""
      });
    } catch (e) {
      vigolium.log.warn("ai-fp-filter: confirmFinding failed: " + e);
      return result; // pass through on error
    }

    // Drop high-confidence false positives silently
    if (!confirmation.confirmed && confirmation.confidence === "high") {
      vigolium.log.info(
        "ai-fp-filter: dropping FP '" + result.info.name + "' — " + confirmation.reasoning
      );
      return null;
    }

    // Annotate the result with LLM verdict
    var prefix = confirmation.confirmed ? "[AI-verified] " : "[AI-uncertain] ";
    var suffix = "\n\nAI reasoning: " + confirmation.reasoning;
    if (confirmation.false_positive_indicators && confirmation.false_positive_indicators.length > 0) {
      suffix += "\nFP indicators: " + confirmation.false_positive_indicators.join(", ");
    }

    return {
      url: result.url,
      matched: result.matched,
      request: result.request,
      response: result.response,
      info: {
        name: prefix + result.info.name,
        description: result.info.description + suffix,
        severity: result.info.severity
      }
    };
  }
};
