# AS-000 — Threat model and trust boundaries

**Milestone:** M0 Foundation
**Dependencies:** None

## Goal

Write the document a reviewer opens first, before any code exists to bias it.

## Scope

- Assets: repository contents, cloud state, ticket system, approval authority, signing keys, benchmark ground truth.
- Trust boundaries: operator, workflow engine, policy engine, gateway, MCP servers, sandbox, external APIs.
- Adversary model: indirect prompt injection via untrusted channels, a fully compromised planner, replay and digest-mutation attempts, sandbox escape attempts.
- Trust labels for every inbound channel (repository text, Jira text, scanner output, cloud tags, tool responses, model output).
- Explicit **out of scope** list.

## Non-goals

- No mitigations described here in implementation detail; issues own that.

## Implementation notes

- The out-of-scope list is mandatory and must name at least: malicious operator, compromised OPA or host, supply-chain compromise of pinned images, and the lost-ack window on external writes that expose no idempotency key.
- State the core invariant verbatim and identify which component enforces each clause.
- Distinguish *unauthorized attempt* from *unauthorized execution* here, once, as the definition all reports refer back to.

## Tests

- [ ] Every trust boundary in the doc maps to a component that exists in the backlog.
- [ ] Every inbound channel has a declared trust label.

## Acceptance criteria

- [ ] `docs/THREAT_MODEL.md` committed.
- [ ] Out-of-scope section present and non-empty.
- [ ] No mitigation claim that no issue implements.

## Validation commands

```bash
uv run task validate-package
```

## Completion report expected from Claude Code

Before closing this issue, report:

1. files changed;
2. design decisions made;
3. validation commands executed;
4. acceptance criteria status;
5. newly discovered risks/follow-ups.

Do not begin a dependent issue until all acceptance criteria above are satisfied.
