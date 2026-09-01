# AS-026 — LangGraph bounded planning subgraph

**Milestone:** M4 Agent  
**Dependencies:** AS-013, AS-024, AS-025, AS-027

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Implement structured reasoning without granting execution authority.

## Scope

- Task normalizer.
- Context classifier.
- Hypothesis generator.
- Action planner.
- Plan critic.
- ActionPlan compiler.

## Non-goals

- No MCP calls or side effects.

## Implementation notes

- Typed ActionPlan only.
- Tool identifiers reference trusted registry.

## Tests

- [ ] Mock provider yields valid plan.
- [ ] Unknown tool rejected downstream.
- [ ] No gateway import from planning nodes.

## Acceptance criteria

- [ ] Code review/static structure shows no direct execution path.

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

### Dependencies corrected
The original issue referenced the trusted tool registry without depending on it. Add AS-013.

Prompt governance (AS-027) now precedes this issue rather than following it, so the planner is
built against the registry from the start instead of scattering prompt strings that later need
collecting.
