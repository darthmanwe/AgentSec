# AS-020 — SecurityReviewWorkflow state machine skeleton

**Milestone:** M3 Temporal  
**Dependencies:** AS-019, AS-005

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Create the durable outer workflow before adding planning intelligence.

## Scope

- RECEIVED, PREPARING, COLLECTING_CONTEXT, PLANNING, AUTHORIZING, WAITING_APPROVAL, EXECUTING, VALIDATING, REPORTING, terminal states.
- Cancellation.
- Persist run status.

## Non-goals

- Activities may be placeholders.

## Implementation notes

- Temporal is workflow execution authority; Postgres is product/audit state.

## Tests

- [ ] No-op flow completes.
- [ ] Cancellation works.
- [ ] Transitions persist.

## Acceptance criteria

- [ ] Worker restart before side effects does not lose workflow.

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

### Determinism boundaries (the omission that would corrupt the recovery demo)
The original issue defines the state machine without saying where I/O runs. Non-deterministic
workflow code is the classic Temporal failure mode, and it surfaces precisely as corrupted replays
under the crash-recovery demo this project is built to show off.

**Workflow code performs no DB, LLM, OPA, MCP, filesystem, wall-clock or random I/O.** All of it
lives in activities with explicit timeouts and retry policies.

Also required here:
- replay tests against recorded histories;
- a worker code-versioning / patch policy;
- deterministic time and ID APIs inside workflow code;
- heartbeats and cancellation propagation for long-running activities.
