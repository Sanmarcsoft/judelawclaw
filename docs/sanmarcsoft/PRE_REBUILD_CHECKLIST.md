# OpenClaw VM Pre-Rebuild Checklist

**Audience:** Sanmarcsoft operators rebuilding the autonomous-Zorin OpenClaw VM
on the NixOS host `10.0.0.112`.
**Authority:** Persona Zorin owns the deploy; Persona Q owns the intel.
**Source intel:** `MEMORY/RESEARCH/judelawclaw-sync-redteam-2026-05-12.md`
(24-claim RedTeam ParallelAnalysis, 56 findings, 5 CRITICAL, 5 HIGH).

This document is the **deployment-time companion** to the in-tree code
hardening. The code-level gates ship on the `hotfix/pre-rebuild-hardening`
branch. Items in this checklist are environment / orchestration concerns
that the codebase cannot enforce by itself.

---

## Block-the-rebuild gates (CRITICAL)

Do **not** rebuild the VM until every item below is checked off.

### 1. OTLP exporters disabled at VM startup (RedTeam B1)

`opentelemetry-exporter-otlp-proto-grpc` and `opentelemetry-exporter-otlp-proto-http`
are bundled by default. They will silently export spans/metrics to
`http://localhost:4317` (gRPC) or `http://localhost:4318` (HTTP) unless
`OTEL_EXPORTER_OTLP_ENDPOINT` is set, and Sanmarcsoft has no documented OTel
collector.

**Required:** the systemd unit `openclaw-vm.service` on `10.0.0.112` MUST set:

```ini
Environment="OTEL_SDK_DISABLED=true"
```

Verify after rebuild from the host:

```sh
ssh root@10.0.0.112 'systemctl show openclaw-vm.service -p Environment'
```

The smoke test probe `otlp-disabled` reads this env from inside the VM and
fails if the value is absent or falsy.

### 2. Rollback marker captured (RedTeam G5)

Before the new image is built, capture the running VM image and tag it
explicitly so the rollback path is one command:

```sh
ssh root@10.0.0.112 '
  docker tag openclaw-vm:current openclaw-vm:rollback-pre-merge-2026-05-12 \
    && docker images | grep openclaw-vm
'
```

If the deployment uses a Nix flake build instead of a Docker tag, the
equivalent is to record the current `flake.lock` SHA in
`MEMORY/RESEARCH/openclaw-rollback-2026-05-12.lock` before rebuilding.

### 3. ChromaDB audit of `agent_zorin_memory` (RedTeam D1/D2)

The synced upstream commit `24d8dbd8` fixes a memory-system sensitive-info
filter that was broken in the version Zorin has been running until now.
Anything Zorin wrote into `agent_zorin_memory` may contain unredacted
prompts, credentials, or PII.

**Required:** before the rebuild, query the collection for high-entropy
strings, API-key patterns, and email addresses, and either redact or
delete the offending entries.

```sh
# From the PAI host:
curl -s http://10.0.0.12:18000/api/v2/tenants/default_tenant/databases/default_database/collections \
  | jq '.[] | select(.name=="agent_zorin_memory")'
```

This audit is Zorin's responsibility — do not delegate.

### 4. Persistent volume preservation (RedTeam G3)

The rebuild MUST preserve:

* Zorin chat history (location TBD — inventory on .112 before rebuild)
* `openclaw-share` bind mount
* ChromaDB pointer file inside the VM (the collection itself lives at
  `10.0.0.12:18000`, but the VM may cache a collection ID)
* Agent workspace state under `/var/lib/openclaw/` (or equivalent)

Capture an explicit volume manifest and confirm it survives the rebuild
via `ls -la` post-deploy.

### 5. Smoke test runs against a throwaway VM first (RedTeam G1)

The behavioural diff is 1,423 files. Even with all the code-level gates,
the rebuild can break in non-obvious ways.

```sh
python scripts/smoke_test_zorin.py --gateway http://127.0.0.1:18789
```

Exit code semantics:

* `0` — all probes green; rebuild is safe to promote
* `1` — at least one probe failed; investigate before promoting
* `2` — gateway unreachable; do not proceed under any circumstance

---

## Strongly-recommended gates (HIGH)

### 6. Read commit `80eec50d` for host-validation default (RedTeam E1/E2)

The synced codebase contains a host-validation refactor: "host校验改成通过开关和白名单控制" (host validation switched to switch + whitelist control). Identify the
default behaviour of that switch before rebuild:

* If default-deny: Sanmarcsoft IPs must be added to the baked-in whitelist
  (the VM image must ship with a Sanmarcsoft-shaped allowlist).
* If default-off: post-rebuild Zorin is running with **no** host
  validation, which is weaker than today.

### 7. Diff `resonantos-alpha` overlay paths (RedTeam F1)

The Zorin identity overlay (`SOUL.md`, `IDENTITY.md`, EI, voice) binds to
upstream hook paths on the `feature/1-zorin-1.0` branch of
`Sanmarcsoft/resonantos-alpha`. Upstream renamed module paths in the 482
commits. Verify every overlay binding still resolves before the rebuild;
silent overlay breakage is the single highest-probability mid-rebuild
failure mode.

### 8. Submodule pointer verification (RedTeam F2)

`resonantos-alpha` pulls `Gstack`, `PAI`, and `MHH-EI` as submodules. Each
must resolve and remain compatible with the synced base.

---

## What the codebase already enforces

These items ship on `hotfix/pre-rebuild-hardening` and need no operator
action beyond merging the branch into `develop` before rebuild.

| RedTeam item | Code change | File |
|---|---|---|
| A1 — gitcode.com mutable dep | Pinned to SHA `3d1334c4` | `pyproject.toml` |
| B2/C3 — Huawei OBS skill bucket | Fail-closed allowlist defaults | `jiuwenclaw/server/runtime/skill/skill_manager.py` |
| C1/C2 — audit-write for tool dispatch | New audit module (Python port) | `jiuwenclaw/security/audit.py` |
| G1/G5 — smoke test + rollback gate | 10-probe smoke script | `scripts/smoke_test_zorin.py` |

The audit module is **landed but not yet wired** into the tool dispatch
sites (`command_tools.py`, `search_tools.py`, `web_fetch_tools.py`,
`memory_tools.py`). Wiring is the second commit on this branch, to be
landed before the rebuild promotes to production.

---

## Authority and propagation

Per the Persona → Autonomous propagation principle in effect since
2026-05-12: Zorin (PAI session) owns Autonomous Zorin (the OpenClaw VM).
Q delivers intel and stands by; Zorin drives the deploy.

Out of scope for this checklist: the PTT bridge agent registry cleanup
(`master-control` mispointing, `zorin` health) — queued for after the
rebuild outcome is stable.
