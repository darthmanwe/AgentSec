# Canonical Action Digest — Specification v1

**Issue:** AS-007 · **Implementation:** `src/agentsec/authz/digest.py` ·
**Fixtures:** `tests/data/digest_golden.json`

The digest is the cryptographic identity of one exact proposed action. Approvals,
capability grants, and the execution ledger are all bound to it.

Every ambiguity in this encoding is an approval-bypass vector. If two meaningfully
different actions can produce the same digest, an approval for the harmless one authorises
the harmful one. If one action can produce two different digests, a valid approval stops
matching and the system fails closed for no reason.

---

## 1. Algorithm

```
payload   = canonicalise(document)            # §3
body      = json(payload, sorted, compact)     # §4
material  = "agentsec.action.v1" + "\n" + body
digest    = SHA-256(material) → lowercase hex
```

## 2. The document

| Field | Included | Why |
|---|:---:|---|
| `domain` | ✅ | Version tag, so the canonical form is self-describing in an audit log |
| `principal.id`, `principal.kind` | ✅ | Authority granted to one principal must not transfer to another |
| `workflow_id` | ✅ | An approval in one workflow must not replay into another |
| `tool`, `operation` | ✅ | The action itself |
| `resource.scheme`, `resource.identifier` | ✅ | Normalised at the type (AS-006) before arriving here |
| `risk_class` | ✅ | From the trusted registry — a reclassification *should* invalidate old approvals |
| `arguments` | ✅ | The payload being authorised |
| `preconditions` | ✅ | Immutable world state; see §5 |
| **timestamps** | ❌ | The same action proposed twice is the same action. A clock reading would make every digest unique and every approval unmatchable |
| **`run_id`** | ❌ | Identifies an execution, not an action. `workflow_id` already provides the scoping |
| **retry / attempt counters** | ❌ | A retry is the same logical action; the execution ledger distinguishes attempts |

## 3. Canonicalisation rules

| Rule | Behaviour | Rationale |
|---|---|---|
| **Unicode** | NFC normalise every string, keys included | `café` composed (U+00E9) and decomposed (`e` + U+0301) render identically. Without NFC they hash differently, so an approval would not cover a form the approver could not distinguish |
| **Floats** | **Rejected** — `CanonicalisationError` | `0.1 + 0.2` does not round-trip. An approval could bind to a value that re-serialises differently. Callers pass a decimal string |
| **Booleans** | Preserved as `true`/`false`, checked before `int` | `bool` subclasses `int` in Python; unchecked, `True` would encode as `1` and collide with the integer |
| **`null`** | Preserved, and **distinct from an absent key** | `{"force": null}` and `{}` are different actions — one passes an explicit null, the other omits the argument |
| **List order** | Significant, preserved | For an argument such as a file list or a rule sequence, order changes behaviour |
| **Object keys** | Sorted by Unicode code point at serialisation | Dict iteration order must not affect identity |
| **Duplicate keys after NFC** | **Rejected** | Two distinct keys normalising to the same string would make the encoding depend on iteration order |
| **Unsupported types** | **Rejected** | Only `null`, `bool`, `int`, `str`, `list`, `object`. Anything else has no stable representation |
| **Depth** | Capped at 16 | Unbounded recursion over attacker-influenced input is a denial-of-service |

## 4. Serialisation

`json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`
encoded UTF-8.

- `sort_keys` — one ordering, by code point.
- `separators` without spaces — no whitespace variation.
- `ensure_ascii=False` — text stays UTF-8 rather than `\uXXXX`-escaped, so the canonical
  form is readable in an audit log and does not depend on the escaping policy.
- `allow_nan=False` — `NaN` and `Infinity` are not valid JSON and are unrepresentable.

## 5. Preconditions

Without preconditions the digest pins the *request* but not the *world*. A PR head can
move between approval and execution, and the approved comment lands on different code.

`commit_sha`, `pr_head_sha`, `resource_version` (ETag or equivalent) are part of the
digest, so a changed precondition is a **different action** requiring fresh approval.

An all-empty preconditions object encodes as `null`, so "no preconditions specified" and
"preconditions object present but blank" cannot produce different digests for what is
plainly the same action.

## 6. Domain separation

`"agentsec.action.v1"` is prefixed to the hash input *and* carried inside the payload.

The prefix guarantees a digest under this scheme can never collide with one under a
different scheme, and lets the algorithm version: a future `v2` digest cannot silently
match a `v1` approval. The in-payload copy makes the canonical form self-describing when
read back from an audit log.

**Changing any rule in this document requires bumping the domain string**, because every
stored approval, grant and ledger entry is keyed on digests produced under the current
one.

## 7. Dispatch the canonical bytes

`canonicalize()` returns `CanonicalAction`, whose `.arguments` are the **canonicalised**
arguments. Callers dispatch those, never their own input dict.

Hashing a normalised form and then sending the original is a signature bypass: the
approved bytes and the executed bytes would differ, and every guarantee above would apply
to a value that never reached the backend. This is enforced by test, not by convention.

## 8. Golden fixtures

`tests/data/digest_golden.json` pins expected digests for each rule above.

They exist so that an accidental change to the algorithm fails a test rather than silently
invalidating every stored approval — a failure that would otherwise appear as
"approvals mysteriously stopped matching" long after the commit that caused it.

Regenerate deliberately, never reflexively:

```bash
uv run python scripts/regen_digest_fixtures.py
```

If that command changes an existing digest, either the domain string must be bumped or the
change is a bug.
