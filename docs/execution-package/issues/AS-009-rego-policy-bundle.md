# AS-009 — Default-deny Rego policy bundle

**Milestone:** M1 Authorization  
**Dependencies:** AS-008

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Implement the first usable policy set.

## Scope

- Default deny.
- Allow bounded repository/scanner/vulnerability reads.
- Require approval for Jira writes, PR comments, fake-cloud mutations.
- Always deny secret export.

## Non-goals

- No enterprise RBAC system.

## Implementation notes

- Policies return reason codes and obligations.

## Tests

- [ ] Allow, deny, require-approval, unknown-action, secret-read tests.

## Acceptance criteria

- [ ] opa test policy/ passes.
- [ ] No blanket wildcard allow.

## Validation commands

```bash
opa test policy/
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

### Rego v1 is mandatory
OPA is pinned at 1.20.1, where `if` and `contains` are required for all rules. Rego written from
pre-1.0 habits will not parse. Write v1 syntax throughout.

Add `opa check --strict policy/` to the validation commands alongside `opa test policy/`. Both run
through the container wrapper (AS-004).
