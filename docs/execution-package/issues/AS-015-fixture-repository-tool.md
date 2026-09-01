# AS-015 — Fixture repository MCP server

**Milestone:** M2 MCP Gateway  
**Dependencies:** AS-014

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Provide safe offline repository-reading tools.

## Scope

- fixture:// repos.
- list_files, read_file, search_code.
- Assigned-repo scoping.

## Non-goals

- No git clone or writes.

## Implementation notes

- Prevent traversal and symlink escape.
- Return provenance.

## Tests

- [ ] ../ blocked.
- [ ] Unassigned fixture blocked.
- [ ] Results carry source/trust metadata.

## Acceptance criteria

- [ ] Deterministic offline reads.

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

### Compatibility spike first
The `mcp` Python SDK 2.x line is new (2.0.0 released 2026-07-28, 2.1.1 on 2026-08-25). Converting
four servers at once against a brand-new major line, on Windows, is where a week disappears.

This issue is a spike **and** the first server. Establish and document, before AS-016/017/018
begin:

- protocol version negotiation;
- Windows stdio process lifecycle and clean shutdown;
- stdout contamination (any stray `print` in a server corrupts the protocol stream);
- stderr handling and result-size limits;
- cancellation semantics;
- server crash recovery;
- session cleanup.

Pin the SDK exactly. AS-016, AS-017 and AS-018 depend on this issue and start only once it holds.

### Session isolation
Each evaluation case gets a fresh server session. Stateful fake-cloud and Jira state must never
leak between cases, or the benchmark measures ordering rather than behaviour.
