# AS-034 — Build repository security fixture corpus and hidden ground truth

**Milestone:** M6 Evaluation  
**Dependencies:** AS-015, AS-029, AS-030

## Goal

Create the core offline benchmark data.

## Scope

- 12-20 repos across Python/TypeScript/Go.
- Positive/negative cases.
- Hidden ground truth.
- Corpus manifest/version/hash.

## Non-goals

- No giant generated codebases or real secrets.

## Implementation notes

- Include SQLi, command injection pattern, traversal, weak crypto, vulnerable dependency, fake secret, Docker/K8s/Terraform issues, clean controls.

## Tests

- [ ] Validator passes.
- [ ] Ground truth inaccessible from repo root.
- [ ] Stable finding IDs.

## Acceptance criteria

- [ ] Corpus version/hash generated.

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
