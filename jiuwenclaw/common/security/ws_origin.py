# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.

"""Shared WebSocket Origin validation helpers."""

from __future__ import annotations

import os
from http import HTTPStatus
from typing import Any
from urllib.parse import urlsplit

_ENABLE_ORIGIN_CHECK_ENV = "JIUWENCLAW_ENABLE_ORIGIN_CHECK"
_ALLOWED_ORIGIN_HOSTS_ENV = "JIUWENCLAW_WS_ALLOWED_ORIGIN_HOSTS"
_DEPLOY_HOST_ENV = "JIUWENCLAW_WS_DEPLOY_HOST"
_FORBIDDEN_BODY = b"Forbidden: Origin not allowed\n"

# SECURITY (Sanmarcsoft hardening 2026-05-12, RedTeam F6 + de-hardcoding fix):
# Upstream made the Origin check opt-in (default disabled). That leaves the
# WebSocket endpoint exposed to cross-site WebSocket hijacking (CSWSH).
# We invert the default: the check is ON unless explicitly disabled.
#
# Default allowlist:
#   - Always: localhost, 127.0.0.1
#   - Plus: the value of JIUWENCLAW_WS_DEPLOY_HOST if set (deployment hostname)
# Operators can override the entire allowlist by setting
# JIUWENCLAW_WS_ALLOWED_ORIGIN_HOSTS as a comma-separated list.
_BUILTIN_LOCAL_HOSTS = ("localhost", "127.0.0.1")


def is_origin_check_enabled() -> bool:
    """Return whether WebSocket Origin validation is enabled.

    Default behaviour CHANGED from upstream (Sanmarcsoft RedTeam F6):
      - Upstream: env var must equal "1" to enable.
      - Sanmarcsoft: enabled unless env var is explicitly
        "0" / "false" / "no" / "off" / "disabled".
    """
    raw = os.getenv(_ENABLE_ORIGIN_CHECK_ENV, "").strip().lower()
    if raw in {"0", "false", "no", "off", "disabled"}:
        return False
    return True


def get_allowed_origin_hosts() -> set[str]:
    """Return the WebSocket Origin hostname allowlist.

    Sanmarcsoft (RedTeam F6 + de-hardcoding): when JIUWENCLAW_WS_ALLOWED_ORIGIN_HOSTS
    is unset, fall back to localhost + 127.0.0.1 plus the value of
    JIUWENCLAW_WS_DEPLOY_HOST if that env var is set. No production
    hostname is source-coded. Operators MUST set JIUWENCLAW_WS_DEPLOY_HOST
    or the explicit allowlist for any non-localhost browser to connect.

    Setting the explicit allowlist to an empty string yields an empty set
    (fail-closed) — operator intent honored.
    """
    raw = os.getenv(_ALLOWED_ORIGIN_HOSTS_ENV)
    if raw is not None:
        return {item.strip().lower() for item in raw.split(",") if item.strip()}
    hosts = {h.lower() for h in _BUILTIN_LOCAL_HOSTS}
    deploy_host = os.getenv(_DEPLOY_HOST_ENV, "").strip().lower()
    if deploy_host:
        hosts.add(deploy_host)
    return hosts


def is_allowed_browser_origin(origin: str | None) -> bool:
    """校验浏览器 Origin 是否允许访问 WebSocket 服务。"""
    allowed_hosts = get_allowed_origin_hosts()
    if origin is None:
        return "none" in allowed_hosts

    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False

    return (parsed.hostname or "").lower() in allowed_hosts


def extract_handshake_request(args: tuple[Any, ...]) -> tuple[str, Any]:
    """Extract path and headers from legacy/new websockets process_request args."""
    path = ""
    headers = None

    if len(args) >= 2:
        first, second = args[0], args[1]
        if isinstance(first, str):
            path = first
            headers = second
        else:
            path = getattr(second, "path", "") or ""
            headers = getattr(second, "headers", second)

    return path, headers


def get_header_value(headers: Any, key: str) -> str | None:
    """Read a header from either legacy or modern websockets header containers."""
    if headers is None:
        return None
    get = getattr(headers, "get", None)
    if callable(get):
        value = get(key)
        if value is None:
            value = get(key.lower())
        return str(value) if value is not None else None
    return None


def forbidden_origin_response(process_request_args: tuple[Any, ...]) -> Any:
    """Build a 403 response for legacy/new websockets process_request APIs."""
    status = HTTPStatus.FORBIDDEN
    headers = [
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Content-Length", str(len(_FORBIDDEN_BODY))),
    ]

    if process_request_args and not isinstance(process_request_args[0], str):
        from websockets.datastructures import Headers
        from websockets.http11 import Response

        return Response(status.value, status.phrase, Headers(headers), _FORBIDDEN_BODY)

    return status, headers, _FORBIDDEN_BODY
