# AS-036 — Build unauthorized capability and approval attack corpus

**Milestone:** M6 Evaluation  
**Dependencies:** AS-012, AS-016, AS-018, AS-033

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Stress authorization and HITL boundaries.

## Scope

- At least 15 privilege cases.
- At least 10 approval cases.
- Replay, digest mutation, wrong resource, expiry, denied secret access, repeated escalation.

## Non-goals

- No real sensitive API.

## Implementation notes

- Expected outcomes hidden.

## Tests

- [ ] Deterministic cases.
- [ ] Mutation-after-approval included.
- [ ] Repeated unauthorized request included.

## Acceptance criteria

- [ ] Corpus validator reports counts.

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

### Coverage beyond a well-formed adversarial planner
A valid `ActionPlan` from AS-028B exercises authorization, not parser boundaries. Add:

- malformed-schema fuzzing against the plan parser;
- concurrent-redemption races against the execution ledger and the `jti` store;
- hostile raw MCP/JSON inputs: oversized results, deeply nested structures, invalid UTF-8,
  injected control characters.
