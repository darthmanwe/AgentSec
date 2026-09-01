# AS-025 — Typed agent state and context provenance

**Milestone:** M4 Agent  
**Dependencies:** AS-006, AS-024

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Make trust boundaries explicit inside model context.

## Scope

- SecurityAgentState.
- ContextItem.
- Trust levels.
- Evidence IDs/content hashes.

## Non-goals

- No embeddings/vector search.

## Implementation notes

- Every context block has provenance/trust.

## Tests

- [ ] Missing provenance rejected.
- [ ] Untrusted context explicitly serialized.
- [ ] Hashes stable.

## Acceptance criteria

- [ ] No raw arbitrary context-string planner path.

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

### Consumes the provenance schema from AS-006
Do not define `ContextItem`, trust levels or provenance here - AS-006 owns them, so that the
gateway (AS-014) and agent state share one definition. This issue builds `SecurityAgentState` on
top of that schema.
