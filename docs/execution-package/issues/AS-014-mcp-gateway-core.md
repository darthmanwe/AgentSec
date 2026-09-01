# AS-014 — MCP Gateway core authorization path

**Milestone:** M2 MCP Gateway  
**Dependencies:** AS-011, AS-013

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Create the only supported path from AgentSec to MCP tools.

## Scope

- Capability verification.
- Typed arg validation.
- Timeout/result-size enforcement.
- Dispatch.
- Audit event.

## Non-goals

- No real GitHub/Jira yet.

## Implementation notes

- Never call backend if verification fails.
- Return trust label.

## Tests

- [ ] No capability/bad args => zero backend calls.
- [ ] Timeout recorded.
- [ ] Oversized result handled.

## Acceptance criteria

- [ ] Denied request never reaches backend.

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

### Inherits the end-to-end denial assertions from AS-012
AS-012 cannot assert "no backend call happened" because no gateway exists at that point. Those
assertions live here: for every denial path, prove zero backend calls occurred, using a backend
double that records every invocation.

### Capability enforcement: gateway-only (ADR)
The issues implied both gateway redemption *and* backend-side signature verification. Two
verifications of a single-use token conflict directly with the execution ledger in AS-011/AS-022.

**Decision: gateway-only enforcement over a private subprocess boundary.** The MCP servers are
local stdio subprocesses the gateway spawns; they are not independently reachable, so backend
verification would add ceremony without a real trust boundary. The one genuinely external backend
(AS-033, GitHub) cannot verify our grants at all, which settles it.

Record this as an ADR, with backend-side verification named as the extension point for a
remotely-reachable backend. It is a decision, not an omission.
