# AS-022 — Workflow idempotency for side effects

**Milestone:** M3 Temporal  
**Dependencies:** AS-007, AS-020, AS-016, AS-018

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Guarantee retries do not duplicate externally visible/mutable actions.

## Scope

- Idempotency key = workflow ID + action digest.
- Persist attempts/results.
- Replay-safe behavior.

## Non-goals

- No generalized distributed transaction framework.

## Implementation notes

- Use tool-specific idempotency.

## Tests

- [ ] Forced retries create one Jira item / one cloud mutation.
- [ ] Audit shows retry but one logical effect.

## Acceptance criteria

- [ ] At-most-once logical side effect in tested scenarios.

## Validation commands

```bash
ruff check .
```

```bash
mypy src
```

```bash
pytest -q
```

## Completion report expected from Claude Code

Before closing this issue, report:

1. files changed;
2. design decisions made;
3. validation commands executed;
4. acceptance criteria status;
5. newly discovered risks/follow-ups.

Do not begin a dependent issue until all acceptance criteria above are satisfied.

---

## Amendments (rev 2)

### Logical-execution ledger
Idempotency keyed on workflow ID + action digest alone is not sufficient: two *intentionally*
identical actions in one workflow would collide. Key the ledger on

`operation_id = workflow_id + action_digest + plan_step_occurrence`

- First request writes `PENDING`.
- Completion writes `COMPLETED` with the cached result.
- An identical retry hits the ledger **before** capability redemption and returns the cached
  result, or enters reconciliation if still `PENDING`.
- Re-issuing a capability is permitted only to resume the same `operation_id`.

This ordering is what allows single-use capabilities (AS-011) and durable retries to coexist.

### Claim honestly: at-most-once, not exactly-once
External APIs that expose no idempotency key (GitHub's issue-comment endpoint among them) cannot
give exactly-once. A hidden operation marker plus a pre-write lookup narrows the window but cannot
close it. Reports and README say **at-most-once with reconciliation**, and the threat model states
the residual lost-ack window.
