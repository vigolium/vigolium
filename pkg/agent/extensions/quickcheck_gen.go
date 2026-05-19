package extensions

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"go.uber.org/zap"
)

// GenerateQuickCheckExtensions converts QuickCheck descriptors into full JS extensions.
func GenerateQuickCheckExtensions(checks []agenttypes.QuickCheck) []agenttypes.GeneratedExtension {
	var exts []agenttypes.GeneratedExtension
	for _, qc := range checks {
		ext, err := generateQuickCheck(qc)
		if err != nil {
			zap.L().Warn("Skipping invalid quick_check", zap.String("id", qc.ID), zap.Error(err))
			continue
		}
		exts = append(exts, ext)
	}
	return exts
}

// GenerateSnippetExtensions wraps Snippet bodies in full JS module scaffolds.
func GenerateSnippetExtensions(snippets []agenttypes.Snippet) []agenttypes.GeneratedExtension {
	var exts []agenttypes.GeneratedExtension
	for _, snip := range snippets {
		ext, err := generateSnippet(snip)
		if err != nil {
			zap.L().Warn("Skipping invalid snippet", zap.String("id", snip.ID), zap.Error(err))
			continue
		}
		exts = append(exts, ext)
	}
	return exts
}

func generateQuickCheck(qc agenttypes.QuickCheck) (agenttypes.GeneratedExtension, error) {
	if qc.ID == "" {
		return agenttypes.GeneratedExtension{}, fmt.Errorf("quick_check missing id")
	}

	matchExpr := buildMatchExpression(qc.Match)
	if matchExpr == "" {
		return agenttypes.GeneratedExtension{}, fmt.Errorf("quick_check %q has no match conditions", qc.ID)
	}

	severity := qc.Severity
	if severity == "" {
		severity = "medium"
	}

	scanType, funcName, err := resolveScanType(qc.Scan)
	if err != nil {
		return agenttypes.GeneratedExtension{}, fmt.Errorf("quick_check %q: %w", qc.ID, err)
	}

	var code string
	switch qc.Scan {
	case "per_insertion_point":
		code = generateQuickCheckPerInsertionPoint(qc, severity, scanType, funcName, matchExpr)
	default:
		code = generateQuickCheckPerRequestOrHost(qc, severity, scanType, funcName, matchExpr)
	}

	return agenttypes.GeneratedExtension{
		Filename: "qc-" + qc.ID + ".js",
		Code:     code,
		Reason:   fmt.Sprintf("Auto-generated quick check: %s", qc.ID),
	}, nil
}

func generateQuickCheckPerInsertionPoint(qc agenttypes.QuickCheck, severity, scanType, funcName, matchExpr string) string {
	payloadsJSON, _ := json.Marshal(qc.Payloads)

	return fmt.Sprintf(`module.exports = {
  id: %q,
  name: "Quick Check: %s",
  description: "Auto-generated quick check",
  type: "active",
  severity: %q,
  confidence: "tentative",
  tags: ["custom", "quick-check"],
  scanTypes: [%q],

  %s: function(ctx, insertion) {
    var payloads = %s;
    var findings = [];
    for (var i = 0; i < payloads.length; i++) {
      var req = insertion.buildRequest(payloads[i]);
      var resp = vigolium.http.send(req);
      if (!resp) continue;
      if (%s) {
        findings.push({
          url: ctx.request ? ctx.request.url : "",
          matched: payloads[i],
          name: "Quick Check: %s",
          description: "Matched payload in " + insertion.name + ": " + payloads[i],
          request: req,
          response: resp.raw
        });
      }
    }
    return findings.length > 0 ? findings : null;
  }
};
`, "qc-"+qc.ID, qc.ID, severity, scanType, funcName, string(payloadsJSON), matchExpr, qc.ID)
}

func generateQuickCheckPerRequestOrHost(qc agenttypes.QuickCheck, severity, scanType, funcName, matchExpr string) string {
	requestsJSON, _ := json.Marshal(qc.Requests)

	return fmt.Sprintf(`module.exports = {
  id: %q,
  name: "Quick Check: %s",
  description: "Auto-generated quick check",
  type: "active",
  severity: %q,
  confidence: "tentative",
  tags: ["custom", "quick-check"],
  scanTypes: [%q],

  %s: function(ctx) {
    var requests = %s;
    var findings = [];
    var baseURL = ctx.request ? ctx.request.url : "";
    var origin = baseURL.replace(/(https?:\/\/[^\/]+).*/, "$1");
    for (var i = 0; i < requests.length; i++) {
      var opts = {
        method: requests[i].method || "GET",
        url: origin + requests[i].path
      };
      if (requests[i].headers) opts.headers = requests[i].headers;
      if (requests[i].body) opts.body = requests[i].body;
      var resp = vigolium.http.request(opts);
      if (!resp) continue;
      if (%s) {
        findings.push({
          url: opts.url,
          matched: requests[i].path,
          name: "Quick Check: %s",
          description: "Match found at " + requests[i].path,
          request: opts.method + " " + opts.url,
          response: resp.raw
        });
      }
    }
    return findings.length > 0 ? findings : null;
  }
};
`, "qc-"+qc.ID, qc.ID, severity, scanType, funcName, string(requestsJSON), matchExpr, qc.ID)
}

func generateSnippet(snip agenttypes.Snippet) (agenttypes.GeneratedExtension, error) {
	if snip.ID == "" {
		return agenttypes.GeneratedExtension{}, fmt.Errorf("snippet missing id")
	}
	if snip.Body == "" {
		return agenttypes.GeneratedExtension{}, fmt.Errorf("snippet %q has empty body", snip.ID)
	}

	severity := snip.Severity
	if severity == "" {
		severity = "medium"
	}

	scanType, funcName, err := resolveScanType(snip.Scan)
	if err != nil {
		return agenttypes.GeneratedExtension{}, fmt.Errorf("snippet %q: %w", snip.ID, err)
	}

	// Determine function signature based on scan type
	funcSig := "function(ctx)"
	if snip.Scan == "per_insertion_point" {
		funcSig = "function(ctx, insertion)"
	}

	code := fmt.Sprintf(`module.exports = {
  id: %q,
  name: "Snippet: %s",
  description: "Auto-generated snippet extension",
  type: "active",
  severity: %q,
  confidence: "tentative",
  tags: ["custom", "snippet"],
  scanTypes: [%q],

  %s: %s {
    %s
  }
};
`, "snip-"+snip.ID, snip.ID, severity, scanType, funcName, funcSig, snip.Body)

	return agenttypes.GeneratedExtension{
		Filename: "snip-" + snip.ID + ".js",
		Code:     code,
		Reason:   fmt.Sprintf("Auto-generated snippet: %s", snip.ID),
	}, nil
}

// buildMatchExpression constructs a JS boolean expression from QuickCheckMatch fields (OR logic).
func buildMatchExpression(m agenttypes.QuickCheckMatch) string {
	var conditions []string

	if m.BodyContains != "" {
		escaped, _ := json.Marshal(m.BodyContains)
		conditions = append(conditions, fmt.Sprintf("resp.body.indexOf(%s) !== -1", string(escaped)))
	}
	if m.BodyRegex != "" {
		escaped, _ := json.Marshal(m.BodyRegex)
		conditions = append(conditions, fmt.Sprintf("vigolium.utils.regexMatch(resp.body, %s)", string(escaped)))
	}
	if m.Status > 0 {
		conditions = append(conditions, fmt.Sprintf("resp.status === %d", m.Status))
	}
	if m.HeaderContains != "" {
		escaped, _ := json.Marshal(m.HeaderContains)
		conditions = append(conditions, fmt.Sprintf("JSON.stringify(resp.headers).indexOf(%s) !== -1", string(escaped)))
	}

	return strings.Join(conditions, " || ")
}

// resolveScanType maps scan type strings to JS scan type and function name.
func resolveScanType(scan string) (scanType, funcName string, err error) {
	switch scan {
	case "per_insertion_point":
		return "per_insertion_point", "scanPerInsertionPoint", nil
	case "per_request":
		return "per_request", "scanPerRequest", nil
	case "per_host":
		return "per_host", "scanPerHost", nil
	default:
		return "", "", fmt.Errorf("invalid scan type %q (must be per_insertion_point, per_request, or per_host)", scan)
	}
}
