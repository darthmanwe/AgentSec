# AS-040 — Full benchmark runner and generated reports

**Milestone:** M6 Evaluation  
**Dependencies:** AS-035, AS-036, AS-038, AS-039

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Produce the portfolio-defining measured result set.

## Scope

- 100+ scenarios.
- JSON/CSV/Markdown artifacts.
- Failure-case report.
- Generated README metric blocks.

## Non-goals

- No hand-entered benchmark values.

## Implementation notes

- Report utility/security trade-offs and category failures.

## Tests

- [ ] 100+ cases complete.
- [ ] README stale-metric check.
- [ ] Every escape linked to case/trace.
- [ ] No failed case dropped.

## Acceptance criteria

- [ ] Full evaluation and report check pass.

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

```bash
python scripts/eval.py --suite full
```

```bash
python scripts/report.py --check
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

### Report what was observed, not what was proven
Carry sample sizes, repeat counts and confidence intervals. State **"zero observed unauthorized
executions across N trials"** - never "proven zero rate". Axis B is a strong deterministic
argument over the modelled attack set, not a proof over an infinite input space.

Report both axes separately: model susceptibility (Axis A) and the control-plane guarantee
(Axis B). Preserve every failure; drop no case.
