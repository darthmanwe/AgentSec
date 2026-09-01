# AS-001 — Bootstrap Python project and quality gates

**Milestone:** M0 Foundation  
**Dependencies:** None

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Create the smallest clean Python 3.12+ foundation for AgentSec.

## Scope

- Create pyproject.toml and uv-compatible dependency management.
- Create src/agentsec package.
- Configure Ruff, mypy strict, pytest, pytest-asyncio, pre-commit.
- Add Makefile shortcuts.

## Non-goals

- No API, DB, LLM, Temporal, OPA, MCP, or orchestration yet.

## Implementation notes

- Use src-layout.
- Disallow untyped defs in owned code.
- Keep dependencies minimal.

## Tests

- [ ] Package import test.
- [ ] Config files parse.
- [ ] Mypy runs.

## Acceptance criteria

- [ ] uv sync succeeds.
- [ ] ruff passes.
- [ ] mypy passes.
- [ ] pytest passes.

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

### Task runner: uv, not make
`make` is not installed on the target machine and is not assumed. Provide a cross-platform task
interface via `uv run task <name>` (`check`, `test`, `lint`, `typecheck`, `opa-test`,
`validate-package`, `eval`). A Makefile may exist as optional convenience only; nothing in the
backlog may depend on it.

### Also created here
- `docs/adr/` with a decision-record template. The master prompt instructs recording an ADR on
  architectural conflict, so the location must exist from the start.
- `.github/workflows/ci.yml` running lint, typecheck, tests, the package validator, and (once it
  exists) the deterministic Axis-B eval. CI must pass with **no credentials configured** - that
  constraint is what keeps the "no mandatory API key" rule honest rather than aspirational.
- `scripts/preflight.ps1` verifying Docker daemon, pinned images present, uv environment, WSL
  resource caps, and `gh` auth.

### Environment
Set `UV_PROJECT_ENVIRONMENT` to a path outside the OneDrive-synced tree. It must be set by the
shell or task runner, **not** in `.env` - uv does not read `.env` for its own configuration.
