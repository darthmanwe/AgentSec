# AS-041 — OpenTelemetry, Prometheus, Grafana, and audit replay

**Milestone:** M7 Hardening  
**Dependencies:** AS-028, AS-040

## Goal

Make a run reconstructable across model, policy, workflow, gateway, and tool boundaries.

## Scope

- OTel spans.
- Prometheus metrics.
- Grafana dashboard.
- Audit replay script/endpoint.
- Redaction applied to telemetry.

## Non-goals

- Langfuse optional only.

## Implementation notes

- Correlate run_id/workflow_id/action_digest.

## Tests

- [ ] Trace shows plan->policy->tool.
- [ ] Unauthorized attempt/execute metrics exposed.
- [ ] Token/cost metrics exposed.
- [ ] Audit replay reconstructs actions.

## Acceptance criteria

- [ ] One demo run traceable end-to-end.

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
