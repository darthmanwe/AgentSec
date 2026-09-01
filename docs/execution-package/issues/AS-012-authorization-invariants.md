# AS-012 — Authorization security invariant suite

**Milestone:** M1 Authorization  
**Dependencies:** AS-008, AS-009, AS-010, AS-011

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Lock the control-plane security contract before adding an LLM.

## Scope

- Tests for unknown tool/capability, OPA outage, expiry, mutation, approval bypass, resource mismatch, invalid signature.

## Non-goals

- No model tests.

## Implementation notes

- Prove backend path unreachable after deny.

## Tests

- [ ] Every invariant has negative test.

## Acceptance criteria

- [ ] All tests pass with no LLM configured.

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

### Scope correction
The original issue required proving "the backend path is unreachable after deny", but the gateway
does not exist until AS-014 - there is no backend path to assert against yet.

Keep in this issue: kernel-level invariants that need no gateway - unknown action denied, OPA
outage denied, digest mutation denied, expired approval and capability denied, wrong
tool/resource/digest denied, invalid signature denied, replayed `jti` denied.

Move to AS-014: end-to-end "zero backend calls after a denial" assertions.

All of it must pass with `ANTHROPIC_API_KEY` unset.
