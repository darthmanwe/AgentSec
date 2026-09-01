# AS-005 — PostgreSQL schema and migrations

**Milestone:** M0 Foundation  
**Dependencies:** AS-002, AS-004

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Create the authoritative product and audit persistence model.

## Scope

- SQLAlchemy 2 async.
- Alembic.
- runs, action_plans, action_attempts, policy_decisions, approvals, capability_grants, tool_executions, model_calls, findings, artifacts, audit_events.

## Non-goals

- No vector or graph storage.

## Implementation notes

- Indexes on run_id, action_digest, idempotency_key, created_at.
- Audit events append-only by service convention.

## Tests

- [ ] Migration upgrade/downgrade.
- [ ] Unique/idempotency constraints.

## Acceptance criteria

- [ ] Fresh DB migrates.
- [ ] Representative records round-trip.

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

### Trimmed scope
The original issue specified eleven tables before any consumer existed, which guarantees
rewriting `findings` and `artifacts` once M6 defines what they hold. Create only what S0/S1
consume:

`runs`, `action_plans`, `action_attempts`, `policy_decisions`, `approvals`,
`capability_grants`, `capability_jti_uses`, `execution_ledger`, `audit_events`.

`tool_executions`, `model_calls`, `findings` and `artifacts` are created by the issues that first
use them. Alembic makes incremental migration cheap; speculative schema is not.

### New tables
- `capability_jti_uses` - single-use redemption record for capability grants (AS-011).
- `execution_ledger` - logical-operation ledger keyed on `operation_id` (AS-022). This is what
  makes single-use capabilities compatible with Temporal retries; without it they deadlock.
