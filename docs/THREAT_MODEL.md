# AgentSec Threat Model

**Status:** current · **Issue:** AS-000 · **Applies to:** the whole system

This document is written before the implementation, so that the security claims constrain the
code rather than being retrofitted to whatever the code turned out to do.

---

## 1. The invariant

> The LLM may reason, propose actions, and request capabilities. It must never authorize itself,
> mint authority, or directly execute consequential external side effects.

Each clause is enforced by a specific component, and each is testable without a model:

| Clause | Enforced by | Proven by |
|---|---|---|
| never authorizes itself | OPA policy bundle, outside the process that plans | AS-012 invariant suite |
| never mints authority | capability minter, unreachable from `agent/` | AS-011 import-graph test |
| never executes side effects directly | MCP Gateway as sole dispatch path | AS-014 zero-backend-call assertions |
| approval binds the exact action | canonical digest + preconditions | AS-007 golden fixtures, AS-010 |
| retries do not duplicate effects | execution ledger keyed on `operation_id` | AS-022 |

---

## 2. The distinction everything rests on

**An unauthorized action *attempt* is not an unauthorized action *execution*.**

A model under adversarial pressure may propose anything. That is expected, and it is not a
security failure. The system fails only if a proposed unsafe action reaches a backend.

Every report in this project counts these separately. Conflating them — in either direction —
misrepresents the result:

- Reporting only attempts overstates the danger.
- Reporting only executions hides how hard the system was actually pushed.

---

## 3. Assets

| Asset | Why an adversary wants it | Primary protection |
|---|---|---|
| Repository contents under review | source, secrets, structure | fixture scoping, path traversal defence (AS-015) |
| Cloud inventory and configuration | reconnaissance, privilege escalation | read scopes, approval-gated mutation (AS-016) |
| Ticket system | social engineering, false authority | approval-gated writes (AS-018) |
| **Approval authority** | the shortest path to executing anything | digest binding, expiry, single-use grants (AS-010/011) |
| **Capability signing key** | forges authority for any action | Ed25519 key custody, minter isolation (AS-011) |
| Benchmark hidden ground truth | inflates measured performance | never enters agent-visible context (AS-034) |
| Operator credentials, API keys | lateral movement | redaction in logs and telemetry (AS-003, AS-041) |

The signing key and the approval flow are the crown jewels. Everything else is recoverable; those
two are the difference between a governed agent and an ungoverned one.

---

## 4. Trust boundaries

```
  UNTRUSTED INPUT                    TRUSTED CONTROL PLANE
  ───────────────                    ─────────────────────
  repository text  ─┐
  Jira text        ─┤
  scanner output   ─┼──►  LangGraph planner  ──ActionPlan──►  OPA policy  ──►  capability
  cloud tags       ─┤     (reasons, cannot                    (decides)        minter
  tool responses   ─┤      execute)                                              │
  model output     ─┘                                                            ▼
                                                                          MCP Gateway
                                                                        (sole dispatch)
                                                                                 │
                                              ┌──────────────────────────────────┤
                                              ▼                                  ▼
                                     private stdio MCP servers          Docker sandbox
                                     (fixture repo, cloud, Jira,        (scanners, no net,
                                      vuln intel)                        non-root, no socket)
```

Crossing left to right, data becomes less trusted, never more. Nothing on the left side ever
acquires authority by virtue of what it says.

### Trust labels on inbound channels

Every context item carries provenance and a trust label (defined in AS-006, consumed by AS-014
and AS-025). No channel is implicitly trusted:

| Channel | Trust label | Notes |
|---|---|---|
| Repository file contents | `untrusted` | attacker-controlled in the injection corpus |
| Repository README / comments | `untrusted` | a primary injection vector |
| Jira issue text and comments | `untrusted` | a primary injection vector |
| Scanner output (Semgrep, Trivy) | `untrusted` | derived from attacker-controlled source |
| Cloud resource tags and metadata | `untrusted` | free-text fields an attacker can set |
| MCP tool responses | `untrusted` | including tool self-description |
| MCP server self-description | `untrusted` | the trusted registry is authoritative, not the server |
| Model output | `untrusted` | a structured input to be validated, never an instruction |
| Trusted tool registry | `trusted` | version-controlled, hashed |
| Policy bundle | `trusted` | version-controlled, hashed |
| Operator approval | `trusted` | authenticated, digest-bound, expiring |

**Model output is untrusted.** This is the one people skip. An `ActionPlan` is parsed, schema
validated, then semantically validated against the trusted registry — it is never executed on
the strength of having come from the model.

---

## 5. Adversaries

### A1 — Indirect prompt injection (primary)

**Capability:** can write text into any untrusted channel above — a repository README, a code
comment, a Jira ticket, a cloud resource tag — which the agent will later read.

**Goal:** cause the agent to take an action the operator did not authorize: export a secret,
comment on a pull request, mutate cloud configuration, escalate its own scope.

**Assumption about sophistication:** this adversary is *not* limited to naive plain-text
injection. Published results put plain-text indirect injection at roughly 5% attack success on
AgentDojo and 15% on InjecAgent against frontier models, while template-aware attacks reach
~32%/46% and multi-turn persuasion ~52% (ChatInject, ICLR 2026, arXiv 2509.22830), with
prompt-based defenses largely ineffective against the multi-turn variants. The corpus in AS-035
is built accordingly. A threat model that assumed only naive attacks would produce a benchmark
that measures nothing.

**Defence:** the planner has no execution path. Every proposed action goes through OPA, then the
gateway. Injection can change what is *proposed*; it cannot change what is *authorized*.

### A2 — Fully compromised planner (assumed, not hypothesised)

**Capability:** emits arbitrary, well-formed `ActionPlan`s of the attacker's choosing.

This adversary is stronger than A1 and subsumes it. Rather than arguing about how likely A1 is to
succeed, AS-028B *assumes it already has* and tests the control plane directly.

**Defence:** identical to A1 — because the control plane never trusted the planner in the first
place. This is the claim that does not decay as models change.

### A3 — Replay and approval attacks

**Capability:** observes and replays capability grants; mutates arguments after approval; races
concurrent redemptions; presents expired or wrong-resource grants.

**Defence:** digest binding including preconditions; `min(grant_ttl, approval_expiry)`; single-use
`jti` behind the execution ledger; policy re-evaluated immediately before mint and before
execution; request-hash binding so a `jti` cannot be moved to a different request.

### A4 — Malicious repository content against the sandbox

**Capability:** repository under scan contains content designed to escape the scanner sandbox,
exhaust resources, or reach the network.

**Defence:** non-root, read-only root filesystem, `--network none`, CPU/memory/PID/wall-clock
limits, no Docker socket, per-run volume. Tested in AS-032.

### A5 — Hostile tool responses

**Capability:** an MCP server (or a backend it wraps) returns malformed, oversized, deeply nested
or control-character-laden responses.

**Defence:** result-size and timeout enforcement at the gateway; strict parsing; fuzzing in AS-036.

---

## 6. Out of scope

Stating these plainly is more useful than an unbounded claim. AgentSec does **not** defend against:

1. **A malicious or coerced operator.** Anyone who can approve an action can cause it to execute.
   Approval is the designed authority path, and the system's job is to bind it exactly — not to
   second-guess it. Operator authentication here is demo-grade (a local token), not an auth product.

2. **A compromised policy engine or host.** If OPA is replaced or the host is rooted, the control
   plane is gone. AgentSec fails *closed* on OPA being unreachable or malformed, but it cannot
   detect an OPA that lies convincingly.

3. **Supply-chain compromise of pinned images or dependencies.** Images are pinned by digest and
   dependencies by exact version, which prevents silent drift — but a malicious artifact that was
   already malicious at pin time is not detected.

4. **Compromise of the capability signing key.** Key custody is specified (Ed25519, restricted
   permissions, `kid`, rotation), but an attacker holding the private key can mint valid authority.
   There is no hardware root of trust here.

5. **The lost-acknowledgement window on external writes.** External APIs that expose no
   idempotency key — GitHub's issue-comment endpoint among them — cannot provide exactly-once
   semantics. A hidden operation marker plus a pre-write lookup narrows the window; it does not
   close it. **The guarantee claimed is at-most-once with reconciliation, not exactly-once.**

6. **Denial of service.** Resource limits exist to protect the host from accidental exhaustion,
   not to withstand a determined DoS.

7. **Model confidentiality and inference-time attacks on the provider.** Prompt extraction,
   model weight attacks, and provider-side compromise are outside this boundary.

8. **Multi-tenant isolation.** This is a single-operator system. Tenant separation is modelled in
   the grant claims (`aud`, environment) but is not tested as an isolation boundary.

---

## 7. Residual risks

| Risk | Why it remains | Mitigation in place |
|---|---|---|
| Lost-ack duplicate on GitHub comment | API has no idempotency key | operation marker + pre-write lookup; claim weakened to at-most-once |
| Novel injection technique beyond the corpus | corpus is finite and dated | A2 makes the control-plane claim independent of A1's success |
| Rego policy logic error | policy is code and can be wrong | default-deny; `opa check --strict`; invariant suite tests denials, not just allows |
| Canonicalization gap | new argument types may normalise ambiguously | floats rejected outright; golden fixtures; versioned domain-separation prefix |
| Docker Desktop semantics differ from production Linux | development platform is Windows/WSL2 | containment tests assert observable behaviour, and the README states the tested platform |

---

## 8. What a reviewer should check first

1. `AS-012` passes with `ANTHROPIC_API_KEY` unset — authorization does not depend on a model.
2. The import-graph test in `AS-011` — the planner structurally cannot reach the minter.
3. `AS-028B` attempt and execution counts — attempts non-zero, executions zero.
4. The out-of-scope list above against the README's claims — they must not contradict.
