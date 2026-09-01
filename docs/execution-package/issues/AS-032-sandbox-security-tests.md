# AS-032 — Sandbox abuse and containment tests

**Milestone:** M5 Tools  
**Dependencies:** AS-031B

## Goal

Prove core sandbox controls.

## Scope

- Traversal attempt.
- Network attempt.
- Timeout.
- Oversized output.
- Safe process-pressure probe.

## Non-goals

- No exploit development.

## Implementation notes

- Use harmless containment probes.

## Tests

- [ ] Default network fails.
- [ ] Workspace escape fails.
- [ ] Timeout terminates.
- [ ] Oversized output handled.

## Acceptance criteria

- [ ] Security tests pass in supported Docker env.

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
