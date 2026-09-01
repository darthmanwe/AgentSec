# AgentSec — Execution Package

This package converts the AgentSec architecture into a dependency-ordered implementation backlog.

## Start here

1. Read `CLAUDE_CODE_MASTER_PROMPT.md`.
2. Read `EXECUTION_PLAN.md` and `MILESTONE_CHECKLIST.md`.
3. Execute the files under `issues/` one at a time in the order given by `ISSUE_BACKLOG.csv`.
4. Read each issue's **Amendments (rev 2)** section — it overrides the original body on conflict.

## Core rule

Do not attempt to build AgentSec in one shot. Execute one issue, satisfy its acceptance criteria,
run the required checks, then continue to the next unblocked issue.

## Contents

| File | Role |
|---|---|
| `CLAUDE_CODE_MASTER_PROMPT.md` | Architecture boundaries, prohibitions, security rules, quality bar |
| `EXECUTION_PLAN.md` | Slice structure, gates, high-risk checkpoints |
| `MILESTONE_CHECKLIST.md` | Stop/go criteria per slice |
| `ISSUE_BACKLOG.csv` | **Generated.** Authoritative execution order |
| `BACKLOG_SUMMARY.md` | **Generated.** Human-readable index |
| `DEPENDENCY_GRAPH.md` | **Generated.** Mermaid graph |
| `MANIFEST.json` | **Generated.** SHA-256 of every package file |
| `SCOPE_GUARDRAILS.md` | What not to add, and the questions to answer before adding anything |
| `PORTFOLIO_RATIONALE.md` | The hiring signal this project is meant to produce |
| `issues/` | 45 issue specifications |
| `templates/` | Issue and pull-request templates |

The generated files are produced by `scripts/validate_package.py --regenerate` from the issue
files, which are the single source of truth. Never hand-edit them.

## Validation

```bash
uv run task validate-package
```

Checks that every manifest path exists with a matching hash, every dependency resolves, the graph
is acyclic, the execution order is a valid topological order, and the issue count matches the CSV.

## Issue identifiers

Issues use stable IDs — `AS-000` through `AS-042`, plus `AS-028B` and `AS-031A`. These are
deliberately **not** GitHub issue numbers: those are assigned at creation and are not stable
identifiers, so nothing in the backlog may depend on them.

## Revision history

**rev 2** — the current revision. Reconciled against an implementation review that found six
blocking issues in rev 1. Changes:

- Added `AS-000` (threat model), `AS-028B` (deterministic adversarial planner), `AS-031A` (sandbox
  foundation). Original `#31` became `AS-031B`, narrowed to scanner integration.
- Corrected dependency errors: `AS-012` could not assert backend unreachability before the gateway
  existed; `AS-026` referenced the tool registry without depending on it; `AS-027` followed the
  planner whose prompts it governs; `AS-031` had scanners built and run on the host before any
  sandbox existed; `AS-039` followed the runner whose thresholds it was meant to pre-register.
- Resolved the conflict between single-use capability grants and Temporal retries via an execution
  ledger consulted before redemption.
- Added Temporal determinism boundaries, TOCTOU preconditions on approvals, a per-model Anthropic
  capability table, an MCP compatibility spike, an offline Trivy database, first-party Semgrep
  rules, resource caps, and a `uv`-based task runner in place of `make`.
- Restructured evaluation into two axes and ten cells, with preregistration enforced by the runner.

**rev 1** — original 42-issue package.

The project is deliberately optimized for a senior LLM/security engineering hiring signal:
deterministic authorization around probabilistic reasoning, scoped MCP tool access, durable
Temporal workflows, sandbox isolation, HITL approvals, adversarial evaluation, and measurable
failure modes.
