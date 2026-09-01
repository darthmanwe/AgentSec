# AS-028 — Integrate planner with Temporal, authorization, and gateway

**Milestone:** M4 Agent  
**Dependencies:** AS-020, AS-026, AS-014, AS-012

## Goal

Complete first vertical slice from task to authorized read-only tool execution.

## Scope

- Collect fixture context.
- Generate ActionPlan.
- Authorize reads.
- Execute via gateway.
- Validate observation.
- Bounded replan on denied substitutable action.

## Non-goals

- No scanners or UI yet.

## Implementation notes

- Policy denial recorded as bounded observation, not authority.

## Tests

- [ ] Benign fixture completes with mock provider.
- [ ] Denied action does not execute.
- [ ] Allowed read goes through gateway.

## Acceptance criteria

- [ ] First full control-path e2e passes offline.

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
