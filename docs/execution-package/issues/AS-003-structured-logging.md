# AS-003 — Structured logging and redaction

**Milestone:** M0 Foundation  
**Dependencies:** AS-001, AS-002

## Goal

Provide correlation-friendly structured logs without leaking sensitive values.

## Scope

- structlog configuration.
- run_id/workflow_id context.
- Recursive redaction of auth headers, API keys, tokens, passwords, private keys.

## Non-goals

- No centralized logging backend.

## Implementation notes

- Implement reusable redactor for nested data.

## Tests

- [ ] Known secret patterns redact.
- [ ] Non-secret fields preserved.

## Acceptance criteria

- [ ] Structured JSON log emitted.
- [ ] Sensitive values redacted.

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
