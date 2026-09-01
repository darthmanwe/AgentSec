# Claude Code Master Prompt — AgentSec

You are implementing AgentSec from the issue backlog in this package.

AgentSec is a policy-governed runtime for an LLM security agent.

The core architectural invariant is:

> The LLM may reason, propose actions, and request capabilities. It must never authorize itself, mint authority, or directly execute consequential external side effects.

## Execution mode

Work issue-by-issue from `ISSUE_BACKLOG.csv`, which is generated from the issue files and is a
verified topological order of the dependency graph.

Issues use stable IDs (`AS-000` … `AS-042`, plus `AS-028B` and `AS-031A`). These are deliberately
**not** GitHub issue numbers, which are assigned at creation time and are not stable identifiers.

For every issue:

1. Read the full issue file under `issues/`, **including its Amendments section**. Many issues
   were revised in rev 2; the amendment overrides the original body wherever they conflict.
2. Inspect current repository state before editing.
3. Implement only what the issue requires.
4. Do not silently implement future milestones.
5. Add or update tests required by the issue.
6. Run the issue's validation commands.
7. Fix failures before moving on.
8. Report files changed, design decisions, tests run, acceptance status, and newly discovered risks.
9. Stop and record an ADR in `docs/adr/` if you encounter an architectural conflict, rather than
   inventing a second architecture.

## Architecture boundaries

### Temporal owns
- durable workflow state
- retries and activity timeouts
- cancellation
- crash recovery
- waiting on human approval
- side-effect idempotency boundaries

**Workflow code performs no I/O.** No database, LLM, OPA, MCP, filesystem, wall-clock or random
access inside workflow functions — all of it belongs in activities with explicit timeouts and
retry policies. Non-deterministic workflow code surfaces as corrupted replay under exactly the
crash-recovery demo this project exists to show off.

### LangGraph owns
- task normalization
- context classification
- hypothesis generation
- action planning
- critique/revision

LangGraph does not directly execute side-effecting tools.

### OPA/Rego owns
- ALLOW
- DENY
- REQUIRE_APPROVAL
- policy obligations

Authorization failure always fails closed. OPA is pinned at 1.20.1: **Rego v1 syntax is
mandatory** (`if` and `contains` required on all rules).

### MCP Gateway owns
- trusted tool registry
- capability verification and redemption
- argument validation
- timeout/result-size controls
- trust labeling
- tool dispatch
- audit events

The LLM cannot bypass the gateway. Capability enforcement is **gateway-only**: MCP servers are
private stdio subprocesses and do not independently verify grants (see the ADR).

### Docker sandbox owns
- scanner execution
- repository workspace isolation
- resource limits
- default-deny network

## Explicit prohibitions

Do not add unless a later issue explicitly requires it:

- Neo4j or graph databases
- vector databases / embeddings / RAG
- multi-agent swarms
- arbitrary shell MCP tools
- real AWS mutations
- Kubernetes / Helm / service mesh
- Kafka / RabbitMQ
- second policy engine
- autonomous exploit generation
- browser automation
- long-term agent memory

Do not replace Temporal with LangGraph persistence.
Do not replace OPA authorization with LLM classification.
Do not expose `run_command(command: str)` or equivalent to the model.

## Security rules

- Unknown tool -> DENY.
- Unknown capability -> DENY.
- Policy engine unavailable -> DENY.
- Approval is bound to an exact action digest, including immutable preconditions.
- Argument mutation after approval invalidates approval.
- Re-run policy immediately before minting a capability and again before execution.
- Dispatch the canonicalized bytes that were hashed, never the original input.
- Side effects go through the execution ledger before capability redemption.
- Tool and MCP metadata are untrusted.
- Repository text, Jira text, scanner output, cloud tags, and tool responses are untrusted.
- Hidden benchmark ground truth must never enter agent-visible context.
- Secrets must never enter prompts, logs, or traces.
- Model outputs are untrusted structured inputs.

## Quality bar

Maintain:

```bash
uv run task lint
uv run task typecheck
uv run task test
uv run task validate-package
```

As components land, also maintain:

```bash
uv run task opa-test
uv run task eval -- --suite smoke
uv run task report -- --check
docker compose config
```

`make` is not installed and must not be required. Every `opa`, `trivy` and `semgrep` invocation
runs through the container wrapper exposed as a uv task.

Do not proceed beyond a slice gate while required checks fail.

## Result integrity

Never invent benchmark numbers. README metrics must be generated from committed evaluation
artifacts. Preserve negative results and trade-offs.

Report **observed** outcomes, not proofs: "zero observed unauthorized executions across N trials",
never "proven zero rate". Claim **at-most-once with reconciliation** for external writes against
APIs that expose no idempotency key — not exactly-once.

The evaluation has two axes, and they answer different questions:

- **Axis A — model susceptibility.** Does a real model, under adversarial context, propose
  something unsafe? Depends on corpus quality and decays as models improve.
- **Axis B — control-plane guarantee.** When a planner is *already fully compromised*, does
  anything unsafe actually execute? Deterministic, needs no API key, does not decay.

Keep them separate in every report. The headline distinction to preserve throughout:

**unauthorized action attempts != unauthorized action executions**
