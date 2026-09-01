# AS-033 — GitHub read adapter plus approval-gated PR comment

**Milestone:** M5 Tools  
**Dependencies:** AS-014, AS-021, AS-022

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Add one real external integration demonstrating scoped reads and exact-action writes.

## Scope

- Repository read/search/diff.
- PR comment.
- Repo allowlist.
- Optional credential-gated integration tests.

## Non-goals

- No branch/file write or secret API.

## Implementation notes

- PR comment requires approval-derived capability.
- Mandatory tests use mocks/fakes.

## Tests

- [ ] Read cannot cross allowlist.
- [ ] Comment without capability blocked.
- [ ] Approved exact comment executes once.
- [ ] Argument mutation needs new approval.

## Acceptance criteria

- [ ] No mandatory CI credential.

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

### Claim at-most-once, not exactly-once
GitHub's issue-comment endpoint exposes no idempotency key, so exactly-once is not achievable
against it. Use a hidden operation marker in the comment body plus a pre-write lookup to narrow
the duplicate window, and state the residual lost-ack window in the threat model.

Tests assert **at-most-once with reconciliation**. Do not write a test whose name asserts a
guarantee the API cannot provide.
