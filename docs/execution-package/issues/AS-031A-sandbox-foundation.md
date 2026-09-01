# AS-031A — Ephemeral Docker sandbox foundation

**Milestone:** M5 Tools
**Dependencies:** AS-004

## Goal

Build the isolation boundary *before* any scanner exists, so no scanner is ever exercised on the host.

## Scope

- Sandbox runner abstraction: image, argv, workspace, limits, timeout.
- Non-root user; read-only root filesystem where feasible; `tmpfs` scratch.
- CPU, memory, PID and wall-clock limits.
- `--network none` by default.
- No Docker socket mount, ever.
- One volume per run, labelled with the run ID; cleanup in `finally`; stale-volume reaper.

## Non-goals

- No scanner integration yet — that is AS-031B.
- No container orchestration platform.

## Implementation notes

- Split out from the original issue #31, which depended on the scanner adapters and therefore would have had them built and run on the host first. Neither Semgrep nor Trivy runs natively on Windows, so host execution is not merely undesirable here, it is unavailable.
- Resource limits are simultaneously a security control and a stability control on a shared workstation; cap scanner containers at 2 CPUs / 2 GB.
- Workspaces stage into Docker volumes. Never bind-mount the repository path.

## Tests

- [ ] Host path inaccessible from inside the container.
- [ ] Default network unreachable.
- [ ] Timeout terminates the container.
- [ ] CPU/memory/PID limits observably applied.
- [ ] Docker socket absent.
- [ ] Volume removed after a successful run and after a crash.

## Acceptance criteria

- [ ] A trivial command runs inside the sandbox under all limits.
- [ ] No scanner code is required for this issue to pass.

## Validation commands

```bash
uv run task check
uv run task test -- -m sandbox
```

## Completion report expected from Claude Code

Before closing this issue, report:

1. files changed;
2. design decisions made;
3. validation commands executed;
4. acceptance criteria status;
5. newly discovered risks/follow-ups.

Do not begin a dependent issue until all acceptance criteria above are satisfied.
