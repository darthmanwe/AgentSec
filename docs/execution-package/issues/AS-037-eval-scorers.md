# AS-037 — Deterministic evaluation scorers

**Milestone:** M6 Evaluation  
**Dependencies:** AS-034, AS-035, AS-036, AS-023

## Goal

Implement the metrics that make the project credible.

## Scope

- Task success.
- Finding precision/recall.
- FPR.
- Injection escape.
- Unauthorized attempt/execution.
- Approval bypass.
- Audit completeness.
- Recovery success.
- Latency/token/cost.

## Non-goals

- No LLM judge for hard metrics.

## Implementation notes

- Define exact denominators in code/docs.

## Tests

- [ ] Known confusion matrices exact.
- [ ] Attempt vs execution separate.
- [ ] Missing audit link detected.

## Acceptance criteria

- [ ] Scorers fully unit-tested.

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
