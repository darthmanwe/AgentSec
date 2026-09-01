# AS-023 — Temporal failure injection harness

**Milestone:** M3 Temporal  
**Dependencies:** AS-020, AS-021, AS-022

## Goal

Test durable execution by intentionally breaking workers/activities.

## Scope

- Kill worker.
- Activity timeout.
- Transient MCP 500.
- Malformed MCP result.
- Duplicate result simulation.

## Non-goals

- No chaos platform.

## Implementation notes

- Deterministic enough for CI subset.

## Tests

- [ ] Workflow resumes.
- [ ] Retryable errors retry.
- [ ] Policy denial not retried.
- [ ] No duplicates.

## Acceptance criteria

- [ ] Recovery report captures induced failure/outcome.

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
