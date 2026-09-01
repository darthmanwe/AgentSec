# AS-002 — Typed configuration and secret-safe settings

**Milestone:** M0 Foundation  
**Dependencies:** AS-001

## Goal

Create typed settings that cleanly separate safe runtime config from secrets.

## Scope

- Pydantic Settings.
- Modes: local/eval/demo.
- SecretStr handling.
- Safe redacted config snapshot.

## Non-goals

- No cloud secret manager integration.

## Implementation notes

- Feature-specific validation.
- Eval mode must work without external credentials.

## Tests

- [ ] Secrets omitted/redacted from safe dump.
- [ ] Missing required values fail clearly.

## Acceptance criteria

- [ ] Safe config snapshot is deterministic.
- [ ] No plaintext secret appears in tests.

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
