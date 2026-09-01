# AS-004 — Development Docker Compose stack

**Milestone:** M0 Foundation  
**Dependencies:** AS-001, AS-002

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Provide reproducible local infrastructure.

## Scope

- PostgreSQL.
- Temporal local server.
- OPA.
- Prometheus.
- Grafana.
- Health checks.

## Non-goals

- No Kubernetes or production deployment.

## Implementation notes

- Keep local credentials clearly marked development-only.

## Tests

- [ ] docker compose config validates.
- [ ] Health checks defined.

## Acceptance criteria

- [ ] Core stack can become healthy locally.
- [ ] No real secrets committed.

## Validation commands

```bash
docker compose config
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

### Image pinning
Pin every image **by digest**, not by tag. A moving tag silently breaks reproducibility of a
published benchmark, which is the one thing this project cannot afford.

### Resource caps (shared workstation)
WSL2 defaults to 50% of host RAM and every logical processor. Write `~/.wslconfig` with
`memory=16GB`, `processors=12`, `swap=8GB`, document it in the README, and have
`scripts/preflight.ps1` verify it.

Give every compose service explicit limits: Postgres 2 CPU / 2 GB, Temporal 2 CPU / 2 GB,
OPA 1 CPU / 512 MB.

### Observability is opt-in
Move Prometheus and Grafana behind a compose profile named `observability`. They are not needed
until AS-041, and S0-S2 should run a three-service stack rather than five.

### Containerised tools
`opa`, `trivy` and `semgrep` binaries are not installed on the host and must not be required.
Every invocation goes through one container wrapper exposed as a uv task. Any issue text that
says `opa test policy/` directly means that wrapper.
