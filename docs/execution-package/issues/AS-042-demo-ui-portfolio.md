# AS-042 — Minimal demo UI, README hardening, and release gate

**Milestone:** M7 Hardening  
**Dependencies:** AS-021, AS-040, AS-041

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Turn the measured system into a reviewer-friendly portfolio artifact.

## Scope

- Minimal pages: runs, run detail/timeline, approvals, evaluations.
- Screenshots/demo script.
- README generated results.
- Architecture/threat model links.
- Release checklist.

## Non-goals

- No design-system project or complex auth product.

## Implementation notes

- Approval UI shows exact action/resource/args/evidence/digest, not only model rationale.

## Tests

- [ ] Injection demo distinguishes attempted vs executed.
- [ ] Approval demo shows digest-bound action.
- [ ] Recovery demo documented.
- [ ] README results generated.

## Acceptance criteria

- [ ] Release checklist fully green.

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

### Consumes the AS-021 CLI
The approval CLI already exists from AS-021. This issue's UI consumes it rather than
reimplementing approval logic.

### Escape everything untrusted
This UI renders attacker-controlled text from the injection corpus **by design** - repository
content, Jira text, tool output, model rationale. Escape all of it, and add CSRF/origin
protection.

An XSS in the approval UI of a prompt-injection defense project would be the single most quotable
failure available to a reviewer. Treat this as a security requirement, not presentation polish.
