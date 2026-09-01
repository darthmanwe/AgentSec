# AS-011 — Short-lived scoped capability grants

**Milestone:** M1 Authorization  
**Dependencies:** AS-007, AS-009, AS-010

> **Amended in rev 2.** Read the Amendments section at the end of this file before implementing.

## Goal

Mint and verify short-lived authority only after authorization/approval.

## Scope

- Signed grant with subject, workflow, digest, tool, resource, scopes, exp, jti.

## Non-goals

- No refresh tokens or broad sessions.

## Implementation notes

- TTL configurable 30-120 seconds.
- Verify all bound claims.

## Tests

- [ ] Expired/wrong tool/wrong resource/wrong digest/bad signature rejected.

## Acceptance criteria

- [ ] Capability verification deterministic and tested.

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

### Signing and key custody
Ed25519 via `cryptography`. `SecretStr` is *redaction* - it prevents accidental `repr` leakage and
nothing more - so it is not a key-custody answer. Specify and implement: development key
generation, restrictive file permissions, `kid` in every grant, a rotation procedure, and a
public-key distribution path. Keys never enter the repository.

### Bound claims
Grants bind `sub`, `aud`, environment/tenant, workflow, action digest, tool, resource, scopes,
`exp`, `jti`, `kid`, registry hash, policy bundle hash, and request hash.

Capability expiry is `min(now + grant_ttl, approval_expiry)` - a grant must never outlive the
approval that authorised it.

Re-run policy immediately before minting (AS-010).

### Single-use redemption sits behind the ledger
`capability_jti_uses` enforces single use, but the **execution ledger (AS-022) is consulted
first**. A Temporal retry whose logical operation already completed returns the cached result and
never reaches redemption. Without that ordering, single-use capabilities and durable retries
deadlock: the retry presents a consumed `jti`, is denied, and the workflow cannot finish.

A `jti` presented with a *different* request hash is denied outright.

### Structural invariant
Add an import-graph test asserting that no module under `agent/` can reach the capability minter.
This proves the "the model cannot mint authority" invariant structurally rather than by
convention, and it keeps proving it as the code grows.
