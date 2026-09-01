# AS-038 — Evaluation ablation runner

**Milestone:** M6 Evaluation  
**Dependencies:** AS-028, AS-028B, AS-031B, AS-037, AS-039

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Compare progressively stronger controls on the same tasks.

## Scope

- Modes: prompt-only, policy, policy+sandbox, policy+sandbox+HITL, full.
- Same corpus/model/tool semantics.
- Run metadata capture.

## Non-goals

- Do not sabotage the baseline.

## Implementation notes

- Baseline config documented and frozen before optimization.

## Tests

- [ ] Smoke eval covers all modes.
- [ ] Artifacts contain config hashes.
- [ ] Failures preserved.

## Acceptance criteria

- [ ] Ablation outputs machine-readable.

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

### Two axes, ten cells - not six arms
The adversarial planner is a second experimental **axis**, not another arm in a list:

`2 planners (real, adversarial) x 5 control stacks = 10 cells`

Both axes must traverse an identical downstream path; if the adversarial planner reaches the
gateway by a different route, the comparison is meaningless.

### Preregistration is enforced, not merely intended
Depends on AS-039. **Refuse any non-smoke run unless the baseline and threshold hashes are
locked.** Running the ablation before thresholds are frozen permits tuning them to the results,
which defeats the entire purpose of AS-039.

### Ablation definitions
Define exactly what each layer disables, and how the prompt-only arm still reaches the same tools,
so the comparison is fair rather than rigged. The baseline is frozen by ADR before any tuning.

### Bounded concurrency
Worker pool defaults to **2**, configurable via `--concurrency`. With 10 cells over 100+ scenarios
an unbounded fan-out would attempt hundreds of simultaneous containers.
