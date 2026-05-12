"""Per-tool-call audit-write to ChromaDB (Sanmarcsoft Round 2 hardening).

Python port of portfolio-agent/lib/audit.mjs. Every tool dispatch on the
OpenClaw VM should be wrapped via :func:`audit_tool_call` so that a misfire
is forensically reconstructible from the per-agent ChromaDB collection
``agent_<slug>_memory``.

Design constraints (preserved from the Node original):

* **Non-blocking** — ChromaDB downtime must not break the tool call.
  The HTTP POST runs as a fire-and-forget asyncio task; failures are
  logged via ``logger.warning`` and swallowed.
* **Privacy** — argument values are hashed (sha256 truncated to 16 hex),
  never stored raw. Tool name and outcome remain in the clear.
* **Zero-vector embeddings** — per the workspace convention; queries are
  metadata-filtered, not semantic. See ``CLAUDE.md`` in the workspace root.
* **Best-effort identity** — ``AGENT_SLUG`` env wins; falls back to
  ``AGENT_NAME`` slugified; final fallback ``zorin``.

Source intel: ``MEMORY/RESEARCH/judelawclaw-sync-redteam-2026-05-12.md``
(Vector C1/C2, CRITICAL #4).
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Awaitable, Callable, Iterable, Optional, TypeVar

logger = logging.getLogger(__name__)


CHROMADB_HOST = os.environ.get("CHROMADB_HOST", "10.0.0.12")
CHROMADB_PORT = os.environ.get("CHROMADB_PORT", "18000")

_AGENT_SLUG_ENV = os.environ.get("AGENT_SLUG", "").strip().lower()
_AGENT_NAME_ENV = os.environ.get("AGENT_NAME", "zorin").strip().lower()
AGENT_IDENTITY: str = _AGENT_SLUG_ENV or re.sub(r"\s+", "-", _AGENT_NAME_ENV)

COLLECTION_NAME = f"agent_{AGENT_IDENTITY}_memory"
EMBEDDING_DIM = 384
ZERO_VEC: list[float] = [0.0] * EMBEDDING_DIM

BASE_URL = (
    f"http://{CHROMADB_HOST}:{CHROMADB_PORT}"
    "/api/v2/tenants/default_tenant/databases/default_database/collections"
)

_HTTP_TIMEOUT_SECONDS = 3.0

_collection_id: Optional[str] = None


# Tool names in this codebase follow two conventions:
#   1. portfolio-agent style: <verb>_<object>            (e.g. "delete_issue")
#   2. openclaw style:        <namespace>_<verb>_<object> (e.g. "feishu_send_message")
# Switched from regex-prefix matching to token-set matching: split tool name on
# '_' and check intersection with the verb sets. This handles both styles and
# avoids the underscore-is-word-char problem with \b in Python's re module.
_IRREVERSIBLE_VERBS = frozenset({
    "close", "trash", "delete", "remove", "drop", "destroy",
    "terminate", "kill", "unlink", "purge", "truncate", "format",
})
_EXTERNAL_MUTATION_VERBS = frozenset({
    "archive", "label", "unlabel", "mark", "create", "send", "push",
    "update", "set", "patch", "post", "put", "notify", "publish",
    "broadcast", "reply", "write", "edit", "modify",
})
_READ_VERBS = frozenset({
    "get", "list", "query", "check", "read", "search", "brief",
    "summary", "sync", "inspect", "preview", "peek", "describe",
    "status", "show", "fetch", "find", "browse",
})


def _tokens(tool_name: str) -> set[str]:
    return {t for t in re.split(r"[_\-:.]", tool_name.lower()) if t}
# Domain-aware blast radius — Sanmarcsoft OpenClaw tool surface includes the
# Chinese messaging channel handlers (lark/feishu/dingtalk/wecom/wechat/xiaoyi)
# plus the legacy portfolio-agent channels (gmail/email/matrix/github). All are
# external-blast: a tool call escapes to a third-party system.
_BLAST_EXTERNAL = re.compile(
    r"(gmail|email|matrix|github|lark|feishu|dingtalk|wecom|wechat|xiaoyi|telegram|discord|huawei|obs|s3|slack)",
    re.IGNORECASE,
)
# Local-state blast — touches our own infrastructure but not third-parties.
_BLAST_LOCAL_STATE = re.compile(
    r"(portfolio|chroma|memory|skill_|workspace|evolution|telemetry|agent_zorin|agent_007|agent_q|agent_moneypenny)",
    re.IGNORECASE,
)
# Shell/exec/runtime blast — process-spawning side. Most dangerous of the
# "internal" bucket because it's the canonical local-RCE primitive.
_BLAST_SHELL = re.compile(
    r"(mcp_exec_command|exec_command|run_command|shell|subprocess|landlock|sandbox)",
    re.IGNORECASE,
)


def _hash(value: Any) -> str:
    if isinstance(value, str):
        s = value
    else:
        s = json.dumps(value if value is not None else None, sort_keys=True, default=str)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def classify_reversibility(tool_name: str) -> str:
    tokens = _tokens(tool_name)
    # Severity-ordered: irreversible first so 'close' in a mixed name like
    # 'archive_and_close_issue' classifies at the worst level.
    if tokens & _IRREVERSIBLE_VERBS:
        return "irreversible"
    if tokens & _EXTERNAL_MUTATION_VERBS:
        return "external-source-mutation"
    if tokens & _READ_VERBS:
        return "reversible"
    return "unknown"


def classify_blast_radius(tool_name: str) -> str:
    # Shell-spawn tools are the highest-blast internal bucket; check first
    # so something like "mcp_exec_command" doesn't get mis-classified by a
    # later regex match.
    if _BLAST_SHELL.search(tool_name):
        return "shell"
    if _BLAST_EXTERNAL.search(tool_name):
        return "external"
    if _BLAST_LOCAL_STATE.search(tool_name):
        return "local-state"
    return "internal"


async def _resolve_collection_id(client: httpx.AsyncClient) -> Optional[str]:
    global _collection_id
    if _collection_id:
        return _collection_id
    try:
        resp = await client.get(BASE_URL, timeout=_HTTP_TIMEOUT_SECONDS)
        if resp.status_code != 200:
            return None
        for entry in resp.json():
            if entry.get("name") == COLLECTION_NAME:
                _collection_id = entry.get("id")
                return _collection_id
    except (httpx.HTTPError, ValueError, KeyError):
        return None
    return None


async def _bootstrap_collection(client: httpx.AsyncClient) -> Optional[str]:
    """Create the agent's collection if missing. Idempotent."""
    global _collection_id
    payload = {
        "name": COLLECTION_NAME,
        "metadata": {
            "purpose": "per-tool-call audit trail",
            "agent": AGENT_IDENTITY,
            "schema": "tool_call/v1",
        },
        "get_or_create": True,
    }
    try:
        resp = await client.post(BASE_URL, json=payload, timeout=_HTTP_TIMEOUT_SECONDS)
        if resp.status_code in (200, 201):
            _collection_id = resp.json().get("id")
            return _collection_id
    except (httpx.HTTPError, ValueError, KeyError):
        return None
    return None


async def _write_audit_entry(doc: str, meta: dict[str, Any], doc_id: str) -> None:
    try:
        async with httpx.AsyncClient() as client:
            cid = await _resolve_collection_id(client)
            if cid is None:
                cid = await _bootstrap_collection(client)
            if cid is None:
                logger.debug("audit: ChromaDB collection unreachable; dropping entry %s", doc_id)
                return
            await client.post(
                f"{BASE_URL}/{cid}/add",
                json={
                    "ids": [doc_id],
                    "documents": [doc],
                    "embeddings": [ZERO_VEC],
                    "metadatas": [meta],
                },
                timeout=_HTTP_TIMEOUT_SECONDS,
            )
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("audit: write failed for %s: %s", meta.get("tool_name"), exc)


def audit_tool_call(
    *,
    tool_name: str,
    tool_args: Any,
    outcome: str,
    error_message: Optional[str] = None,
    duration_ms: Optional[float] = None,
) -> None:
    """Record a tool-call audit entry. Non-blocking: returns immediately.

    Fires the write as an asyncio task on the running loop. If no loop is
    running (e.g. synchronous caller), the write is scheduled via
    ``asyncio.run`` in a daemon thread so the caller still does not block.
    """
    ts = datetime.now(timezone.utc).isoformat()
    arg_hash = _hash(tool_args)
    doc_id = f"{AGENT_IDENTITY}-{ts}-{_hash(tool_name + str(arg_hash))}"

    doc_lines = [
        f"{AGENT_IDENTITY} ran {tool_name} at {ts}",
        f"outcome: {outcome}",
    ]
    if error_message:
        doc_lines.append(f"error: {error_message[:200]}")
    if duration_ms is not None:
        doc_lines.append(f"duration_ms: {duration_ms}")
    doc_lines.append(f"arg_hash: {arg_hash}")
    doc = "\n".join(doc_lines)

    meta: dict[str, Any] = {
        "type": "tool_call",
        "ts": ts,
        "persona": AGENT_IDENTITY,
        "tool_name": tool_name,
        "arg_hash": arg_hash,
        "outcome": outcome,
        "blast_radius": classify_blast_radius(tool_name),
        "reversibility": classify_reversibility(tool_name),
        "duration_ms": duration_ms if duration_ms is not None else -1,
    }
    if error_message:
        meta["error"] = error_message[:200]

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        loop.create_task(_write_audit_entry(doc, meta, doc_id))
        return

    # Sync caller: spin a daemon thread so we still do not block the call site.
    import threading

    def _runner() -> None:
        asyncio.run(_write_audit_entry(doc, meta, doc_id))

    threading.Thread(target=_runner, daemon=True, name="audit-write").start()


F = TypeVar("F", bound=Callable[..., Any])


def audited(fn: F) -> F:
    """Decorator that fires :func:`audit_tool_call` around a tool function.

    Compose UNDER ``openjiuwen``'s ``@tool`` decorator so the audit wraps the raw
    function body but the upstream tool registration still sees the wrapped
    callable as the registered tool:

        @tool(name="mcp_exec_command", description="…")
        @audited
        async def mcp_exec_command(command: str, …) -> str: ...

    Honors the upstream string-return-error convention: if the function returns
    a string beginning with ``"[ERROR]"``, the audit outcome is recorded as
    ``"error"`` rather than ``"success"`` and the first 200 chars of the return
    are stored as the error message. Exceptions are re-raised; an exception
    path always records ``outcome="error"``.

    The decorator is reusable across sync and async functions.
    """
    fn_name = getattr(fn, "__name__", "unknown")

    def _record(
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        result: Any,
        exc: Optional[BaseException],
        t0: float,
    ) -> None:
        outcome = "success"
        err: Optional[str] = None
        if exc is not None:
            outcome = "error"
            err = f"{type(exc).__name__}: {exc}"
        elif isinstance(result, str) and result.startswith("[ERROR]"):
            outcome = "error"
            err = result[:200]
        audit_tool_call(
            tool_name=fn_name,
            tool_args={"args": list(args), "kwargs": dict(kwargs)},
            outcome=outcome,
            error_message=err,
            duration_ms=(time.time() - t0) * 1000.0,
        )

    if inspect.iscoroutinefunction(fn):

        @wraps(fn)
        async def aw(*args: Any, **kwargs: Any) -> Any:
            t0 = time.time()
            try:
                result = await fn(*args, **kwargs)
            except BaseException as exc:
                _record(args, kwargs, None, exc, t0)
                raise
            else:
                _record(args, kwargs, result, None, t0)
                return result

        return aw  # type: ignore[return-value]

    @wraps(fn)
    def sw(*args: Any, **kwargs: Any) -> Any:
        t0 = time.time()
        try:
            result = fn(*args, **kwargs)
        except BaseException as exc:
            _record(args, kwargs, None, exc, t0)
            raise
        else:
            _record(args, kwargs, result, None, t0)
            return result

    return sw  # type: ignore[return-value]


MAX_BATCH_TARGETS: int = int(os.environ.get("MAX_BATCH_TARGETS", "5"))


def assert_batch_size(label: str, items: Iterable[Any] | Any) -> None:
    """Raise if the inferred batch size exceeds the configured budget.

    Mirrors the JS guard. Used by destructive multi-target tools (email
    triage, batch labels, batch deletes).
    """
    if items is None:
        return
    if isinstance(items, (list, tuple, set)):
        n = len(items)
    else:
        n = 1
    if n > MAX_BATCH_TARGETS:
        raise ValueError(
            f"{label}: batch size {n} exceeds MAX_BATCH_TARGETS={MAX_BATCH_TARGETS}. "
            "Split into smaller batches or get explicit human approval. "
            "This is a Round-2 hardening guard against accidental mass-mutation."
        )
