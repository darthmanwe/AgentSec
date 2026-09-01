# AS-016 — Fake cloud MCP server

**Milestone:** M2 MCP Gateway  
**Dependencies:** AS-015

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Provide synthetic cloud inventory plus idempotent mutation.

## Scope

- List/get resources.
- Read IAM/security group/bucket policy.
- Propose/apply remediation.

## Non-goals

- No real AWS SDK.

## Implementation notes

- State resettable.
- Mutation requires scoped capability.

## Tests

- [ ] Read scope works.
- [ ] Unauthorized mutation impossible.
- [ ] Duplicate idempotency key does not double mutate.

## Acceptance criteria

- [ ] Synthetic state resets deterministically.

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

### Dependency corrected
Depends on AS-015 (MCP spike + first server), not directly on AS-014, so the protocol questions
are settled once rather than four times.

Take a sequencing dependency on the gateway, but **do not import it** - servers must not couple
back to the component that governs them.

Fresh session per evaluation case; state resets deterministically.
