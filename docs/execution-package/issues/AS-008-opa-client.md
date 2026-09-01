# AS-008 — OPA policy client with fail-closed semantics

**Milestone:** M1 Authorization  
**Dependencies:** AS-004, AS-006

## Goal

Introduce deterministic external authorization.

## Scope

- PolicyEngine protocol.
- OPA HTTP client.
- Timeout/error handling.
- Decision metadata.

## Non-goals

- No complete policy set yet.

## Implementation notes

- Unreachable or malformed OPA maps to DENY.
- Never fall back to allow.

## Tests

- [ ] ALLOW/DENY/REQUIRE_APPROVAL parsing.
- [ ] Timeout -> DENY.
- [ ] Malformed -> DENY.

## Acceptance criteria

- [ ] Fail-closed invariant covered.

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
