# AS-006 — Authorization domain models

**Milestone:** M1 Authorization  
**Dependencies:** AS-001, AS-002

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Define typed contracts for authorization before policy logic.

## Scope

- Principal, ResourceRef, RiskClass, ActionIntent, AuthorizationRequest, PolicyObligation, PolicyDecision.

## Non-goals

- No OPA client or capabilities yet.

## Implementation notes

- Use Pydantic v2 and strict enums.

## Tests

- [ ] Unknown outcomes rejected.
- [ ] Invalid risk class rejected.
- [ ] Resource normalization tested.

## Acceptance criteria

- [ ] Contracts serialize predictably.
- [ ] No untyped dict escape hatch in critical fields.

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

### Provenance schema lives here
Define `ContextItem`, trust levels and provenance in this issue, not in AS-025. The gateway
(AS-014) returns trust labels at M2, long before agent state exists at M4; if the schema is
defined twice, two incompatible shapes appear and have to be reconciled later.

AS-025 consumes this definition rather than introducing its own.
