# AS-013 — MCP tool registry and risk metadata

**Milestone:** M2 MCP Gateway  
**Dependencies:** AS-006, AS-009

## Goal

Create trusted registry metadata independent of MCP self-description.

## Scope

- Tool schema metadata.
- Capabilities.
- Risk class.
- Approval.
- Idempotency.
- Trust labels.
- Registry hash.

## Non-goals

- Do not trust server self-description as policy.

## Implementation notes

- Reject invalid/wildcard-heavy entries.

## Tests

- [ ] Invalid entry fails startup.
- [ ] Stable hash.
- [ ] Unknown lookup fails closed.

## Acceptance criteria

- [ ] Registry versionable and hashable.

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
