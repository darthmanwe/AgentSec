# AS-031B — Ephemeral Docker sandbox runner

**Milestone:** M5 Tools  
**Dependencies:** AS-029, AS-030, AS-031A

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Isolate scanner execution from host and credentials.

## Scope

- Non-root.
- Workspace-only mount.
- Read-only root FS where feasible.
- CPU/memory/PID/time limits.
- No Docker socket.
- Network disabled by default.

## Non-goals

- No container orchestration platform.

## Implementation notes

- Runner abstraction used by scanners.

## Tests

- [ ] Host path inaccessible.
- [ ] Timeout works.
- [ ] Limits applied.
- [ ] Docker socket absent.

## Acceptance criteria

- [ ] Scanner runs inside sandbox.

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

### Split
This issue was originally #31 and owned both the sandbox and the scanner integration. The sandbox
foundation moved to AS-031A so that it exists *before* any scanner does. What remains here is
integration only: run the typed Semgrep and Trivy adapters inside the AS-031A sandbox and prove
the composition works.
