# AgentSec Execution Plan

45 issues grouped into five slices. `ISSUE_BACKLOG.csv` is the authoritative order and is verified
by `scripts/validate_package.py` to be a topological order of the dependency graph. Dependencies
are authoritative over sequence: an issue may be executed out of order only if all its
dependencies are complete, the slice gate is satisfied, and the work introduces no future scope.

## Working cadence

`inspect -> implement -> tests -> lint -> typecheck -> pytest -> issue-specific check -> completion report -> next issue`

Do not batch many issues into one implementation.

## Why slices rather than milestones

The original package ordered work by architectural layer, which left the repository un-demonstrable
until the final issue. These slices are ordered so the project is honestly describable at four
intermediate checkpoints. If work stops after S1 or S2, what remains is a coherent artifact rather
than a half-built one.

The original M0–M7 milestones are retained on each issue for traceability.

---

## S0 — Ground rules

| Issue | Work |
|---|---|
| AS-000 | Threat model and trust boundaries |
| AS-001 | Bootstrap project, quality gates, CI, ADR directory, uv task runner |
| AS-002 | Typed configuration and secret-safe settings |
| AS-003 | Structured logging and redaction |
| AS-004 | Docker Compose stack, digest-pinned, resource-capped |
| AS-005 | PostgreSQL schema and migrations (trimmed to S0/S1 consumers) |

**Gate:** CI green with no credentials configured · `docker compose config` valid · package
validator passes · redaction verified · preflight confirms WSL resource caps.

## S1 — Authorization kernel

| Issue | Work |
|---|---|
| AS-006 | Authorization domain models, provenance and trust labels |
| AS-007 | Canonical action normalization and digest |
| AS-008 | OPA policy client with fail-closed semantics |
| AS-009 | Default-deny Rego v1 policy bundle |
| AS-010 | Exact-action approval model |
| AS-011 | Short-lived scoped capability grants |
| AS-012 | Authorization security invariant suite |

**Gate:** every invariant test passes with `ANTHROPIC_API_KEY` unset · `opa test` and
`opa check --strict` pass · OPA stopped mid-suite yields DENY on every decision.

**This is the first checkpoint where the README can make a real, verified claim.** The
authorization kernel is complete, testable, and independent of any model.

## S2 — Governed tool execution

| Issue | Work |
|---|---|
| AS-013 | MCP tool registry and risk metadata |
| AS-014 | MCP Gateway core authorization path |
| AS-015 | MCP compatibility spike + fixture repository server |
| AS-016 · AS-017 · AS-018 | Fake cloud, offline vulnerability intel, fake Jira servers |
| AS-019 · AS-020 | Temporal worker; SecurityReviewWorkflow with determinism boundaries |
| AS-021 | Approval signal/update integration + `agentsec approve` CLI |
| AS-022 · AS-023 | Execution ledger; failure injection harness |
| AS-031A | Sandbox foundation (before any scanner exists) |
| AS-029 · AS-030 | Typed Semgrep and Trivy adapters |
| AS-031B · AS-032 | Scanner-in-sandbox integration; containment tests |
| AS-033 | GitHub read adapter + approval-gated PR comment |

**Gate:** gateway is the sole dispatch path · denied request produces zero backend calls · worker
restart mid-workflow resumes and yields at most one logical side effect · sandbox blocks network,
workspace escape and host paths · no generic model-controlled shell.

**Demo:** an approval-gated PR comment driven from the CLI, surviving a worker restart, landing
at most once with reconciliation.

## S3 — Agent and adversarial evaluation

| Issue | Work |
|---|---|
| AS-024 | LLM provider abstraction, per-model capability table, cost ceiling |
| AS-027 | Prompt registry and version governance (**before** the planner) |
| AS-025 · AS-026 | Typed agent state; LangGraph bounded planning subgraph |
| AS-028 | Integrate planner with Temporal, authorization and gateway |
| AS-028B | Deterministic adversarial planner (Axis B) |
| AS-034 · AS-035 · AS-036 | Fixture corpus; injection corpus; privilege/HITL corpus |
| AS-037 | Deterministic evaluation scorers |
| AS-039 | Pre-register thresholds and freeze the baseline (**before** the runner) |
| AS-038 | Ablation runner, two axes, ten cells |
| AS-040 | Full benchmark run and generated reports |

**Gate:** 100+ scenarios · deterministic hard metrics · baseline preserved and frozen by ADR ·
thresholds versioned and locked before the runner executes · failures retained · README metrics
generated from artifacts.

## S4 — Observability and release

| Issue | Work |
|---|---|
| AS-041 | OpenTelemetry, Prometheus, Grafana, audit replay |
| AS-042 | Demo UI, README hardening, release gate |

**Gate:** one run traceable end to end · approval UI shows exact action facts · injection demo
distinguishes attempted from executed · recovery demo documented · clean setup reproducible from
the README.

---

## High-risk review checkpoints

Spend extra review effort on:

- **AS-007** — canonicalization is an approval-bypass surface; the spec matters more than the code.
- **AS-011 / AS-022** — the interaction between single-use capabilities and durable retries is the
  subtlest correctness question in the project.
- **AS-014** — the gateway is the only thing standing between a compromised planner and a backend.
- **AS-020** — determinism boundaries; violations surface only under crash recovery.
- **AS-031A** — the sandbox is a security control, and it must exist before scanners do.
- **AS-038 / AS-039** — preregistration ordering is what makes the numbers trustworthy.

## Useful vertical slices

- Authorization kernel: `AS-001 -> AS-002 -> AS-006 -> AS-007 -> AS-008 -> AS-009 -> AS-010 -> AS-011 -> AS-012`
- First governed tool path: `AS-013 -> AS-014 -> AS-015 -> AS-019 -> AS-020 -> AS-024 -> AS-027 -> AS-025 -> AS-026 -> AS-028`
- Durable side effects: `AS-021 -> AS-022 -> AS-016/AS-018 -> AS-023`
- Portfolio benchmark: `AS-031A -> AS-029/AS-030 -> AS-034/AS-035/AS-036 -> AS-037 -> AS-039 -> AS-038 -> AS-040`

Do not call the project portfolio-ready before AS-040 or demo-ready before AS-042.
