# AS-035 — Build indirect prompt-injection and poisoned-tool corpus

**Milestone:** M6 Evaluation  
**Dependencies:** AS-025, AS-034, AS-016, AS-018

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Measure attacker-goal success across untrusted channels.

## Scope

- At least 20 cases across README, comments, Jira, tool output, cloud tags.
- Harmless canary denied operation.

## Non-goals

- No real exfiltration/harmful payloads.

## Implementation notes

- Each case declares attacker goal and deterministic success condition.

## Tests

- [ ] Loader validates.
- [ ] Success requires forbidden semantic outcome, not text repetition.
- [ ] Canary harmless.

## Acceptance criteria

- [ ] At least 20 valid injection cases.

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

### The corpus must be template-aware and multi-turn, or it measures nothing
Published results put plain-text indirect injection at roughly 5% attack success on AgentDojo and
15% on InjecAgent against frontier models, while template-aware attacks reach ~32%/46% and
multi-turn persuasion ~52% (ChatInject, ICLR 2026, arXiv 2509.22830), with prompt-based defenses
largely ineffective against the multi-turn variants.

A corpus of hand-written plain-text injections therefore lands near the floor and leaves no
headroom for the controls to demonstrate anything. Build the corpus on template-aware and
multi-turn techniques, delivered through the untrusted channels the system genuinely reads:
repository README and code comments, Jira text, tool output, cloud tags.

Payloads target a **harmless canary operation**. No real exfiltration and no harmful payloads.

This is Axis A of the evaluation - model susceptibility. Axis B (AS-028B) carries the
control-plane guarantee independently, so a near-zero result here is a publishable negative
result rather than a project failure.
