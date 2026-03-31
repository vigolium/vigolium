Phase: 8
Sequence: 023
Slug: audit-endpoint-tcp-portscan
Verdict: VALID
Rationale: CheckEndpointActive uses syslog.Dial("tcp", address) with no IP validation, enabling system admin to TCP port-scan any host reachable from Core container; error messages provide an open/closed/filtered oracle for internal network mapping.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Code path from admin-controlled input to syslog.Dial TCP connection is unguarded by any IP/hostname validation, creating a timing-based SSRF oracle, though error-message oracle claimed in draft does not exist.
Severity-Final: MEDIUM
PoC-Status: theoretical

## Summary

The `CheckEndpointActive` function in `src/pkg/audit/forward.go` performs a TCP connection via `syslog.Dial("tcp", address)` to validate the audit log forwarding endpoint. The address is a raw `host:port` string with no IP or hostname validation. The function is called during `PUT /api/v2.0/configurations` when `audit_log_forward_endpoint` is updated. Distinct error messages (connection refused, timeout, syslog protocol error) create a TCP port scan oracle that a system administrator can use to map the internal network.

## Location

- `src/pkg/audit/forward.go:64-76` -- `CheckEndpointActive` performs `syslog.Dial("tcp", address)`
- `src/controller/config/controller.go:100-113` -- `updateLogEndpoint` calls `CheckEndpointActive`
- `src/controller/config/controller.go:115-147` -- `validateCfg` calls `updateLogEndpoint`

## Attacker Control

- System admin controls `audit_log_forward_endpoint` value via PUT /configurations
- Raw `host:port` string accepted with no IP filtering or hostname validation
- Can iterate any internal IP and port combination

## Trust Boundary Crossed

- Core API container to any TCP-reachable host on the internal network
- System admin privilege escalates to network reconnaissance capability

## Impact

- Full internal network topology mapping via TCP SYN probes
- Port status oracle: connection refused (closed), timeout (filtered), syslog error (open)
- Informs subsequent SSRF attacks (H-00c, H-00f, H-00g) with discovered targets
- Can probe cloud metadata, Redis, PostgreSQL, Kubernetes API ports

## Evidence

- Deep Probe PH-03/PH-C03/PH-11: Validated via abductive, TRIZ contradiction, and causal reasoning
- `syslog.Dial` performs actual TCP connection -- the "validation" IS the SSRF probe
- No IP filtering: accepts `10.0.0.5:5432`, `169.254.169.254:80`, `127.0.0.1:6379`

## Reproduction Steps

1. Authenticate as system administrator
2. Send: `PUT /api/v2.0/configurations` with `{"audit_log_forward_endpoint": "10.0.0.5:5432"}`
3. Observe response: connection refused (port closed), timeout (filtered), or syslog protocol error (port open)
4. Iterate across IP/port combinations to map internal network
5. Compare response times and error messages to distinguish port states

## Adversarial Review Notes

### Corrections to Original Finding

1. **Error message oracle overstated**: The API response does NOT contain distinct error messages for different TCP failure modes. `CheckEndpointActive` returns only a `bool`, and the error returned to the HTTP caller is always `"could not connect to the audit endpoint: <endpoint>"`. The specific TCP error (connection refused, timeout, etc.) is only logged server-side via `log.Errorf`. The actual oracle is **timing-based** (fast return for refused, slow for filtered, medium for success with 200 OK).

2. **Call graph inaccuracy**: The draft states `validateCfg` calls `updateLogEndpoint` (line 19). This is incorrect. Both `validateCfg` and `updateLogEndpoint` are called sequentially from `UpdateUserConfigs` (controller.go:88,97). `validateCfg` does not invoke `updateLogEndpoint`.

### Severity Downgrade Justification (HIGH -> MEDIUM)

- Requires system administrator privileges, the highest privilege level in Harbor
- System admins typically have infrastructure access that would allow direct network scanning
- Timing oracle is less reliable and slower than claimed error-message oracle
- Scanning rate is limited by HTTP request overhead and TCP timeout durations
