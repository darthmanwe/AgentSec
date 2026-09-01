# AS-029 — Typed Semgrep scanner adapter

**Milestone:** M5 Tools  
**Dependencies:** AS-014, AS-015, AS-031A

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Add static analysis through a safe typed interface.

## Scope

- scan_repository, scan_path.
- Allowlisted ruleset IDs.
- Timeout.
- Structured parser.

## Non-goals

- No arbitrary CLI string from model.

## Implementation notes

- Build subprocess args deterministically.
- No shell=True.

## Tests

- [ ] Known SQLi fixture detected.
- [ ] Invalid path/ruleset rejected.

## Acceptance criteria

- [ ] No generic command parameter.

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

### Runs in the sandbox from the first commit
Depends on AS-031A (sandbox foundation), which now precedes the scanner adapters. The original
ordering had adapters built and exercised on the host before any sandbox existed - and Semgrep
does not run natively on Windows, so host execution is not merely undesirable, it is unavailable.

### First-party rules only (licensing)
Semgrep's community rules are under the Semgrep Rules License v1.0, limited to internal,
non-competing use - the change that prompted the Opengrep fork. Vendoring them into a public
portfolio repository is not defensible.

Write a first-party ruleset under `policy/semgrep/` targeting only the fixture corpus. This is
better engineering regardless: the evaluation needs deterministic detection against known ground
truth, which a pinned first-party ruleset provides and a drifting upstream registry does not.
Mention Opengrep in the README as a drop-in for anyone wanting registry-equivalent coverage.

### Resources
Pass `--jobs 2` rather than letting Semgrep detect and consume every core.
