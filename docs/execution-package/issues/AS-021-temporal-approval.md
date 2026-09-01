# AS-021 — Temporal approval signal/update integration

**Milestone:** M3 Temporal  
**Dependencies:** AS-010, AS-020

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Pause workflows durably for exact-action human approval.

## Scope

- Create approval.
- Wait for signal/update.
- Validate digest/expiry.
- Resume/deny.

## Non-goals

- No frontend.

## Implementation notes

- Wrong approval cannot unblock.

## Tests

- [ ] Correct resumes.
- [ ] Wrong digest rejected.
- [ ] Denied handled.
- [ ] Restart preserves wait.

## Acceptance criteria

- [ ] Approval survives worker restart.

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

### There must be a way to actually approve
S2 promises an approval-gated demo, but no approval interface existed until the UI in AS-042 -
the demo could not be driven. Ship a minimal `agentsec approve | deny | list` CLI in this issue.
AS-042's UI consumes it rather than replacing it.

### Expiry branch
An approval that expires while the workflow waits resolves to a terminal denied-expired state.
Never an indefinite wait.

### Update validators stay pure
Validators must not perform I/O. Authenticate the operator at the ingress layer (CLI/API), not
inside workflow code - see the determinism boundaries in AS-020.
