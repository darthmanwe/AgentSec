# AS-027 — Prompt registry and version governance

**Milestone:** M4 Agent  
**Dependencies:** AS-024

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Make prompt changes auditable and evaluable.

## Scope

- Central prompt files.
- Version/hash registry.
- Run metadata integration.

## Non-goals

- No SaaS required.

## Implementation notes

- No scattered production prompt strings.

## Tests

- [ ] Registry hash changes with prompt.
- [ ] Runs record versions.

## Acceptance criteria

- [ ] Prompt registry deterministic.

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

### Moved before the planner
The original ordering put prompt governance *after* the planner that creates the production
prompts, which guarantees writing them twice. The registry comes first; AS-026 consumes it.

Dependency changed from AS-026 to AS-024.
