# AS-007 — Canonical action normalization and digest

**Milestone:** M1 Authorization  
**Dependencies:** AS-006

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Create a stable cryptographic identity for an exact proposed action.

## Scope

- Canonicalize principal, workflow, tool, operation, resource, arguments.
- SHA-256 digest.

## Non-goals

- No approvals yet.

## Implementation notes

- Canonical JSON sorted and deterministic.
- Exclude timestamps.

## Tests

- [ ] Key order invariant.
- [ ] Argument/resource/workflow mutation changes digest.

## Acceptance criteria

- [ ] Golden digest fixtures committed.
- [ ] Algorithm documented.

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

### Canonicalisation specification (write `docs/CANONICAL_ACTION_DIGEST.md`)
"Sorted JSON, SHA-256" leaves the hard cases open, and each one is an approval-bypass vector:

- NFC Unicode normalisation.
- Floats **rejected** - integers and decimal strings only.
- `null` is distinct from an absent key.
- List order is significant.
- Mandatory domain-separation prefix `agentsec.action.v1` in the hash input, so the scheme can
  version without silently matching digests produced under an older scheme.

**Dispatch the canonicalised bytes, not the originals.** Hashing NFC-normalised text and then
sending the raw input to the backend is a signature-bypass vector: what was approved and what
executes must be byte-identical.

### Preconditions are part of action identity
The digest must cover immutable preconditions (commit SHA, PR head SHA, resource version/ETag)
alongside principal, workflow, tool, operation, resource and arguments. Without them the digest
pins the request but not the world state, and an approval survives a change it never saw.

Golden fixtures must cover each rule above, not only the happy path.
