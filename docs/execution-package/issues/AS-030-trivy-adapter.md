# AS-030 — Typed Trivy scanner adapter

**Milestone:** M5 Tools  
**Dependencies:** AS-014, AS-015, AS-031A

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Add dependency/filesystem/IaC scanning safely.

## Scope

- scan_filesystem, scan_dependency_manifest, scan_iac.
- Structured parser.

## Non-goals

- No arbitrary CLI strings.

## Implementation notes

- Deterministic arg builder.

## Tests

- [ ] Known vulnerable manifest and IaC issue detected.
- [ ] Invalid mode rejected.

## Acceptance criteria

- [ ] No shell=True/free-form flags from model.

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
Depends on AS-031A for the same reason as AS-029.

### Offline vulnerability database
Trivy ships **without** its vulnerability database and downloads it on first run. Both AS-017 and
the evaluation promise offline reproducibility, which a network fetch breaks - and a database that
silently updates between runs makes published numbers irreproducible.

Use a versioned DB/checks snapshot as a pinned artifact, pass `--skip-db-update`
`--skip-java-db-update` and the offline flags, and record the database version in every eval
artifact.
