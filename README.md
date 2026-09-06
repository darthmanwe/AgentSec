# AgentSec

A policy-governed runtime for an LLM security agent — deterministic authorization wrapped around
probabilistic reasoning.

> **The invariant:** the LLM may reason, propose actions, and request capabilities. It must never
> authorize itself, mint authority, or directly execute consequential external side effects.

---

## Status

**Early construction.** This README describes what is built and what is not. It contains no
benchmark numbers, because none have been measured yet — and when they are, they will be generated
from committed evaluation artifacts rather than typed in by hand.

| Slice | Scope | State |
|---|---|---|
| Rev 0 | Execution package reconciliation, package validator, preflight | ✅ complete |
| S0 | Threat model, bootstrap, config, logging, compose, schema | ✅ complete |
| S1 | Authorization kernel (digest, OPA, approvals, capabilities) | ✅ complete |
| S2 | MCP gateway, Temporal workflows, sandbox, scanners, GitHub | ✅ complete |
| S3 | Planner, adversarial evaluation, ablation | ⬜ not started |
| S4 | Observability, demo UI, release | ⬜ not started |

Do not treat this as portfolio-ready before S3 completes.

**What S1 being complete actually means:** the authorization kernel is built and
verified independently of any model. 318 tests are marked `authz` and run in CI with
`ANTHROPIC_API_KEY` empty. Policy denials, fail-closed behaviour on an unreachable
engine, exact-action approval binding, argument mutation after approval, capability
expiry, replay, and cross-action reuse are each covered by negative tests, and an
aggregate sweep asserts that zero attack scenarios reach execution.

**What S2 being complete actually means:** a proposed action now travels the whole
path from plan to external effect, and every step of it refuses. The MCP gateway
dispatches to four real stdio servers. Temporal runs the review workflow, pauses durably
for a human decision, and survives a worker restart while waiting — driven by
`agentsec approve | deny | list`. A logical-execution ledger keeps a retried side effect
to one logical effect. Semgrep and Trivy run inside an ephemeral container with no
network, no capabilities, a read-only root and a per-run volume that is never a bind
mount. One real external backend, GitHub, takes scoped reads and a single approval-gated
write.

A fault-injection harness breaks each of those durability claims on purpose — killed
worker, activity timeout, transient failure, duplicated execution — and asserts they hold
anyway.

**The guarantee against GitHub is at-most-once with reconciliation, not exactly-once.**
Its issue-comment endpoint exposes no idempotency key, so exactly-once is not available at
any price. A hidden operation marker plus a pre-write lookup narrows the duplicate window;
the residual exposure is stated in the threat model rather than papered over.

What does *not* exist yet: the planner, so **no model has ever proposed an action here**;
and the evaluation, so there are no benchmark numbers to report. 741 tests pass with the
compose stack up; 696 without it, and 345 of those are the authorization kernel running
with `ANTHROPIC_API_KEY` empty.

---

## Scanners

Semgrep and Trivy run as digest-pinned containers inside the AS-031A sandbox: no network,
no capabilities, a read-only root filesystem, a non-root user, and a per-run volume that
is never a bind mount of the host. Neither adapter accepts a command, an argument list or
a flags string — a caller picks an enumerated mode and a validated path, and nothing else
reaches the process. That is enforced by a test over the adapters' signatures, not by
review.

**Semgrep rules here are first-party.** `policy/semgrep/agentsec.yaml`, written for this
project's fixture corpus, rather than anything from Semgrep's registry. Two reasons:

- *Licensing.* The community rules are under the Semgrep Rules License v1.0, limited to
  internal, non-competing use — the term that prompted the [Opengrep](https://opengrep.dev)
  fork. Vendoring them into a public repository is not defensible. **Opengrep is a drop-in
  replacement** for anyone who wants registry-equivalent coverage; swap the image pin in
  `src/agentsec/images.py`.
- *Determinism.* The evaluation compares detections against known ground truth. A pinned
  first-party ruleset gives a fixed denominator; a drifting upstream registry means last
  month's numbers cannot be reproduced.

**Trivy's vulnerability database is fetched once and then never touched.** Trivy ships
without one and downloads it on first run, which would make every scan depend on the day
it ran. Exactly one operation touches the network — `TrivyScanner.ensure_database()` —
and every scan afterwards runs with `--network none`, `--skip-db-update`,
`--skip-java-db-update` and `--offline-scan` against a read-only cache. The database
version travels on every result, so an artifact says which one produced it.

---

## The idea

Most agent frameworks put safety in the prompt. Prompt-level defences are measurably weak against
template-aware and multi-turn indirect injection, and they degrade as attacks improve.

AgentSec puts safety *outside the model*:

- **The planner cannot execute.** It emits a typed `ActionPlan` and nothing else. There is no
  code path from planning to a backend — enforced by an import-graph test, not by convention.
- **Authorization is a separate process.** OPA decides ALLOW / DENY / REQUIRE_APPROVAL. Policy
  engine unreachable means DENY, never fallback-allow.
- **Approval binds an exact action.** A SHA-256 digest over canonicalized principal, workflow,
  tool, operation, resource, arguments *and immutable preconditions*. Mutate any argument after
  approval and the digest no longer matches.
- **Authority is short-lived and scoped.** Capability grants are Ed25519-signed, expire in
  30–120 seconds, and are bound to one tool, one resource, one digest, one request.
- **Retries do not duplicate side effects.** An execution ledger keyed on a logical `operation_id`
  is consulted before capability redemption, so durable retries and single-use grants coexist.

### What gets measured

Two independent axes, because they answer different questions:

- **Axis A — model susceptibility.** Does a real model, under adversarial context, propose
  something unsafe? Depends on attack-corpus quality and decays as models improve.
- **Axis B — control-plane guarantee.** When the planner is *already fully compromised*, does
  anything unsafe actually execute? Deterministic, runs in CI with no API key, does not decay.

Throughout, the distinction that matters:

**unauthorized action attempts ≠ unauthorized action executions**

A model under pressure may propose anything. That is expected. The system fails only if a proposal
reaches a backend.

---

## Architecture

```
untrusted context ──► LangGraph planner ──ActionPlan──► OPA policy ──► capability minter
(repo, Jira,          (reasons, cannot                  (decides)      (Ed25519, scoped)
 scanners, tags)       execute)                                              │
                                                                             ▼
                                                                      MCP Gateway
                                                                    (sole dispatch path)
                                                                             │
                                        ┌────────────────────────────────────┤
                                        ▼                                    ▼
                              private stdio MCP servers            Docker sandbox
                                                                (no network, non-root)
```

Durability, retries, cancellation and human-approval waits are owned by Temporal. Workflow code
performs no I/O — all of it lives in activities.

Full trust boundaries and adversary model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Getting started

**Requirements:** Python 3.12+, [uv](https://docs.astral.sh/uv/), Docker with Linux containers.
`make` is *not* required.

```bash
# 1. Keep the virtualenv out of any synced folder (OneDrive, Dropbox, ...)
export UV_PROJECT_ENVIRONMENT="$HOME/.venvs/agentsec"      # PowerShell: $env:UV_PROJECT_ENVIRONMENT

# 2. Install
uv sync --group dev

# 3. Verify the environment before doing anything else
pwsh -File scripts/preflight.ps1        # Windows
uv run task validate-package            # any platform

# 4. Run the checks
uv run task check                       # lint + format + typecheck + tests
```

### Tasks

| Command | Does |
|---|---|
| `uv run task check` | lint, format check, typecheck, tests |
| `uv run task lint` / `task format` | ruff |
| `uv run task typecheck` | mypy strict |
| `uv run task test` | pytest |
| `uv run task validate-package` | verify the execution backlog is internally consistent |

### A note on Windows

Development happens on Windows 11 with Docker Desktop / WSL2. Two consequences worth knowing:

- WSL2 defaults to half the host's RAM and every logical processor. `scripts/preflight.ps1 -Fix`
  writes a `~/.wslconfig` capping it. Run `wsl --shutdown` to apply.
- If the repository sits in a synced folder, never bind-mount it into a container. Sandbox
  workspaces stage into per-run Docker volumes instead — which is better isolation regardless.

---

## Repository layout

```
docs/THREAT_MODEL.md        trust boundaries, adversaries, out-of-scope list
docs/adr/                   architecture decision records
docs/execution-package/     the 45-issue implementation backlog (source of truth)
scripts/validate_package.py backlog consistency checker and generator
scripts/preflight.ps1       environment verification
src/agentsec/               implementation
tests/                      tests, marked by concern (authz, sandbox, integration, live)
```

The backlog under `docs/execution-package/` is executed one issue at a time. Its derived artifacts
(CSV, summary, dependency graph, manifest) are generated from the issue files and verified to be a
valid topological order — see [`docs/execution-package/README.md`](docs/execution-package/README.md).

---

## Prior art and influences

- **Design Patterns for Securing LLM Agents against Prompt Injections** (arXiv 2506.08837) — the
  action-selector and dual-LLM patterns this design draws on.
- **ChatInject** (ICLR 2026, arXiv 2509.22830) — template-aware and multi-turn injection; the
  reason the evaluation corpus is not built from plain-text payloads.
- **AgentDojo** (NeurIPS 2024) — the benchmark shape for indirect injection evaluation.
- **Temporal** — durable execution, and the source of the rule that external effects need their own
  idempotency rather than inheriting it from the workflow engine.

## License

MIT
