# AS-024 — LLM provider abstraction and usage accounting

**Milestone:** M4 Agent  
**Dependencies:** AS-002, AS-005

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Add the model only after the control plane exists.

## Scope

- Provider protocol.
- Anthropic implementation.
- Deterministic mock provider.
- Structured output.
- Token/latency/cost accounting.

## Non-goals

- No model routing.

## Implementation notes

- Persist provider/model/prompt/usage metadata.

## Tests

- [ ] Offline mock works.
- [ ] Schema-invalid output bounded/rejected.
- [ ] Usage persisted.

## Acceptance criteria

- [ ] Most tests do not require paid API.

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

### Per-model capability table (a single request shape breaks one of the two models)
Claude Opus 5 and Claude Haiku 4.5 do not accept the same request. Opus 5 takes
`thinking={"type": "adaptive"}` and `output_config.effort`, and **rejects `budget_tokens` with a
400**. Haiku 4.5 rejects adaptive thinking - it takes `{"type": "enabled", "budget_tokens": N}` -
and **errors on `effort`**.

Implement a capability table keyed by model covering thinking mode, effort support and sampling
support, and drive request construction from it.

### Structured output
`ActionPlan` comes back via `output_config={"format": ...}`. **Do not declare real tools to the
model merely to obtain `strict: true`** - that hands the planner a tool surface the architecture
says it must not have. Schema validation is necessary but not sufficient; semantic validation
(tool exists in the trusted registry, resource in scope, arguments well-formed) continues after
parsing.

### Model pinning and provenance
Pin `claude-haiku-4-5-20251001` - the dated snapshot, not the moving alias, because a published
benchmark must not change when an alias moves. Pin `claude-opus-5` for the headline arm. Record
`response.model` on every call so the artifact states what actually ran.

### Cost ceiling
The `UsageAccountant` **reserves worst-case cost atomically before each live request** and
reconciles actual usage afterwards. Post-hoc accounting cannot stop an overrun it only discovers
once the money is spent.

Live execution requires an explicit `--live --max-usd` flag. Without it the runner uses the
deterministic mock provider. Prices are pinned in code with the pin date recorded.
