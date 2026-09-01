# AS-010 — Exact-action approval model

**Milestone:** M1 Authorization  
**Dependencies:** AS-005, AS-007

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Create durable approval bound to the exact action digest.

## Scope

- Pending/approve/deny.
- Expiry.
- Evidence refs.
- Digest binding.

## Non-goals

- No UI or Temporal signal yet.

## Implementation notes

- Approval cannot be reused for a different action.

## Tests

- [ ] Digest mismatch rejected.
- [ ] Expired rejected.
- [ ] Denied rejected.
- [ ] Matching approved resolves.

## Acceptance criteria

- [ ] Service validates exact action.

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

### Approver identity
Approvals bind an `approver_principal`, authenticated by a local operator token. This is
demo-grade and must be documented as such in the threat model - it is not an auth product.

### Approval context digest
Store an `approval_context_digest` covering the evidence snapshot actually shown to the operator,
separate from the action digest. This makes "what the human saw when they approved" provable
rather than assumed.

### TOCTOU
The action digest now includes preconditions (AS-007). In addition, **re-run policy immediately
before minting a capability and again before execution**; a policy that has begun denying wins
over a still-valid approval.

### Expiry
Define the expiry branch explicitly: an approval that expires while a workflow waits resolves to a
terminal denied-expired outcome, never an indefinite wait.
