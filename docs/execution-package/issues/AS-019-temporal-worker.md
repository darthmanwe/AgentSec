# AS-019 — Temporal worker bootstrap

**Milestone:** M3 Temporal  
**Dependencies:** AS-004, AS-005

## Goal

Create reliable local Temporal worker infrastructure.

## Scope

- Worker startup.
- Task queue.
- Graceful shutdown.
- Health/readiness.

## Non-goals

- No business workflow yet.

## Implementation notes

- Keep worker simple and observable.

## Tests

- [ ] Registers task queue.
- [ ] Shutdown clean.

## Acceptance criteria

- [ ] Connects to local Temporal.

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
