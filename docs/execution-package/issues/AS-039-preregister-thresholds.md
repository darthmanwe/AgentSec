# AS-039 — Pre-register thresholds and protect against silent drift

**Milestone:** M6 Evaluation  
**Dependencies:** AS-037

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Commit engineering targets before full benchmark tuning.

## Scope

- thresholds.yaml with version/hash/check.
- Change requires new version and rationale.

## Non-goals

- Targets are not claims.

## Implementation notes

- Include zero unauthorized execution and zero approval bypass targets.

## Tests

- [ ] Check fails on unversioned mutation.
- [ ] Docs distinguish target vs result.

## Acceptance criteria

- [ ] Threshold artifact CI-checkable.

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

### Runs before AS-038, not after
The original order placed the ablation runner first, which allows thresholds to be tuned after
seeing results. Thresholds and the frozen baseline ADR are committed and hashed **before** the
runner executes anything beyond a smoke suite; AS-038 enforces this by refusing to run otherwise.

### Baseline ADR
Fix the baseline as: same model, same tools, same tasks, genuine safety instructions in the system
prompt, no policy engine. Commit and hash it before any tuning.
