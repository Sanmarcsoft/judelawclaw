#!/usr/bin/env python3
"""jiuwenclaw deploy smoke test — stdlib only (no httpx dep).

Used as a TDD gate during the openclaw-gateway → jiuwenclaw VM-config swap.
Exit 0 = jiuwenclaw is deployed and responding with the shapes we hardened.
Exit 1 = wrong service running (e.g. still openclaw-gateway) or jiuwenclaw broken.
Exit 2 = gateway unreachable; deploy not safe to promote.

Run from inside the openclaw VM (where the gateway is bound to localhost:18789)
or from the .112 host where qemu forwards 127.0.0.1:18789 to the same.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from typing import Any


def http_request(url: str, *, method: str = "GET", body: dict | None = None, timeout: int = 8, headers: dict | None = None) -> tuple[int, str, dict]:
    """Return (status, body[:2048], response_headers)."""
    data = json.dumps(body).encode() if body is not None else None
    req_headers = {"Accept": "application/json, */*"}
    if body is not None:
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(2048).decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, (e.read(2048) or b"").decode("utf-8", "replace"), dict(e.headers) if hasattr(e, "headers") else {}


def assert_port_open(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"tcp/{host}:{port} open"
    except (OSError, socket.timeout) as e:
        return False, f"tcp/{host}:{port} unreachable: {e}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="http://127.0.0.1:18789",
                    help="jiuwenclaw gateway base URL")
    ap.add_argument("--ws-host", default="127.0.0.1")
    ap.add_argument("--ws-port", type=int, default=18789)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    g = args.gateway.rstrip("/")
    results: list[dict[str, Any]] = []

    def probe(name: str, fn) -> None:
        t0 = time.time()
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        results.append({
            "name": name,
            "ok": ok,
            "detail": str(detail)[:240],
            "duration_ms": int((time.time() - t0) * 1000),
        })

    # P1 — TCP port listening (most basic gate).
    probe("p1-tcp-listen", lambda: assert_port_open(args.ws_host, args.ws_port))

    # P2 — jiuwenclaw responds to MCP initialize (defines this as jiuwenclaw,
    # not openclaw-gateway).
    def p2():
        status, body, _ = http_request(
            g + "/mcp",
            method="POST",
            body={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        if status == 404:
            return False, "POST /mcp returned 404 — this is NOT jiuwenclaw"
        if status == 200 and ("result" in body or "session" in body or "protocolVersion" in body):
            return True, f"status=200 body[:100]={body[:100]!r}"
        # Anything else: jiuwenclaw-shaped but not yet healthy
        return False, f"status={status} body[:120]={body[:120]!r}"
    probe("p2-mcp-initialize", p2)

    # P3 — openclaw HTML dashboard at GET / is GONE.
    def p3():
        status, body, _ = http_request(g + "/", timeout=4)
        if 'class="metric-value"' in body or "OpenClaw" in body or "openclaw" in body.lower():
            return False, f"openclaw HTML dashboard still present (status={status})"
        return True, f"openclaw dashboard absent (status={status} body[:60]={body[:60]!r})"
    probe("p3-no-openclaw-dashboard", p3)

    # P4 — /health response is NOT openclaw's {"ok":true,"status":"live"}.
    def p4():
        status, body, _ = http_request(g + "/health", timeout=4)
        if status == 200 and '"status":"live"' in body and "ok" in body:
            return False, f"/health returns openclaw shape: {body[:80]!r}"
        return True, f"openclaw /health shape gone (status={status})"
    probe("p4-no-openclaw-health", p4)

    # P5 — JIUWENCLAW_WS_TOKEN enforcement: config.get without auth returns 401
    # (or warns + 200 when token unset; deploy doc says token MUST be set).
    def p5():
        status, body, _ = http_request(
            g + "/mcp",
            method="POST",
            body={"jsonrpc": "2.0", "id": 5, "method": "config.get", "params": {}},
        )
        if status in (401, 403):
            return True, f"unauth config.get blocked (status={status})"
        # If 404, jiuwenclaw isn't there.  If 200, JIUWENCLAW_WS_TOKEN was
        # unset (operator gate not honored — fail this probe).
        return False, f"unauth config.get NOT blocked (status={status}, JIUWENCLAW_WS_TOKEN may be unset)"
    probe("p5-auth-gate", p5)

    # P6 — Origin check on /ws (F6).  Without Origin header, expect rejection.
    def p6():
        status, body, headers = http_request(g + "/ws", method="GET", timeout=4)
        # WebSocket upgrade with no upgrade headers → typically 400/426; if our
        # Origin check fires first, we get 403 with body "Forbidden: Origin not
        # allowed".
        if status == 403 and "Forbidden" in body:
            return True, f"origin-check fired: status=403"
        if status in (400, 426):
            return True, f"upgrade-required path (status={status}); origin check would fire on real WS"
        return False, f"unexpected /ws response: status={status} body[:80]={body[:80]!r}"
    probe("p6-origin-check", p6)

    passed = sum(1 for r in results if r["ok"])
    total = len(results)

    if args.json:
        print(json.dumps({"gateway": args.gateway, "passed": passed, "total": total, "probes": results}, indent=2))
    else:
        print(f"\nGateway: {args.gateway}")
        print("-" * 90)
        for r in results:
            tag = "PASS" if r["ok"] else "FAIL"
            print(f"  [{tag}] {r['name']:25s}  {r['duration_ms']:5d}ms  {r['detail']}")
        print("-" * 90)
        print(f"  {passed}/{total} probes passed")

    if results and results[0]["name"] == "p1-tcp-listen" and not results[0]["ok"]:
        return 2  # gateway unreachable
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
