/**
 * @name Ollama - Cloud passthrough base URL not validated against allowlist
 * @description Finds HTTP request construction using cloud proxy base URLs from
 *              environment variables without allowlist host validation.
 *              DFD: DFD-9 (POST /api/experimental/web_fetch → Cloud Proxy → SSRF).
 *              CVE class: CVE-2026-5530, CWE-918.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @id go/ollama/cloud-passthrough-host-not-allowlisted
 * @tags security ssrf
 *       external/cwe/cwe-918
 *       external/cwe/cwe-601
 */

import go

/**
 * A call to os.Getenv for cloud-related config keys.
 */
class CloudEnvRead extends DataFlow::CallNode {
  CloudEnvRead() {
    this.getTarget().hasQualifiedName("os", "Getenv") and
    exists(StringLit s |
      s = this.getArgument(0).asExpr() and
      s.getValue() =
        ["OLLAMA_CLOUD_BASE_URL", "OLLAMA_HOST", "OLLAMA_ORIGINS", "cloudProxyBaseURL"]
    )
  }
}

/**
 * A function that contains an allowlist check.
 */
predicate callerHasAllowlistCheck(DataFlow::CallNode envRead) {
  exists(DataFlow::CallNode check |
    check.getEnclosingCallable() = envRead.getEnclosingCallable() and
    check.getCalleeName() = ["allowedHost", "isAllowedHost", "isHuggingFaceURL",
                              "allowedOrigin", "validateHost", "HasPrefix"]
  )
}

from CloudEnvRead envRead
where not callerHasAllowlistCheck(envRead)
select envRead,
  "Cloud proxy base URL read from environment variable '" +
  envRead.getArgument(0).asExpr().(StringLit).getValue() +
  "' without adjacent allowlist validation — SSRF risk (DFD-9, CVE-2026-5530 class)."
