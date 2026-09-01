# AS-018 — Fake Jira MCP server

**Milestone:** M2 MCP Gateway  
**Dependencies:** AS-015

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Provide local ticket read/write workflows.

## Scope

- search, read_issue, create_issue, comment.
- Idempotency on writes.

## Non-goals

- No real Atlassian dependency.

## Implementation notes

- Writes are approval-gated via capability.

## Tests

- [ ] Read works.
- [ ] Write without valid capability blocked.
- [ ] Duplicate key produces one logical write.

## Acceptance criteria

- [ ] Resettable deterministic state.

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
Depends on AS-015 rather than AS-014, for the reason given there.

Take a sequencing dependency on the gateway, but do not import it.

Fresh session per evaluation case; state resets deterministically.
