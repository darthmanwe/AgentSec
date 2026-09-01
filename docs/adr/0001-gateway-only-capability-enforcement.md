# ADR-0001 — Gateway-only capability enforcement

**Status:** Accepted
**Date:** 2026-08-31
**Issue:** AS-014 (also constrains AS-011, AS-022, AS-033)

## Context

The original backlog implied two enforcement points for capability grants: the MCP Gateway would
verify and redeem a grant, and the backend MCP servers would independently verify its signature.

That is one enforcement point too many. Capability grants are **single-use** — redemption is
recorded in `capability_jti_uses` so a replayed `jti` is rejected (AS-011; adversary A3 in the
threat model). If both the gateway and the backend redeem the same grant, the second redemption
fails against the first, and every legitimate call breaks.

Weakening grants to multi-use to accommodate two verifiers would discard replay protection, which
is one of the properties the project exists to demonstrate.

## Decision

**The gateway is the only component that verifies and redeems capability grants.** MCP servers
trust the gateway because they are private stdio subprocesses that the gateway itself spawns, and
are not independently reachable.

## Alternatives considered

**Backend-side verification as well.** Rejected: it conflicts with single-use redemption as above,
and it buys nothing here. The MCP servers have no independent network surface — there is no path
by which a caller other than the gateway could reach them, so a second check defends against an
adversary the architecture does not admit.

**Multi-use grants with a per-call nonce.** Rejected: this reintroduces replay windows and pushes
the idempotency question down into the tool layer, where the AS-022 execution ledger already
answers it properly at the workflow layer.

**Backend verification for the external adapter only (AS-033, GitHub).** Rejected as incoherent:
GitHub cannot verify AgentSec-issued grants at all — it is an ordinary third-party API. This case
actually settles the general question, because the one genuinely external backend is structurally
incapable of participating in grant verification.

## Consequences

**Makes easy:** single-use redemption works as designed; the ledger-before-redemption ordering in
AS-022 stays coherent; MCP servers stay simple and carry no crypto dependency.

**Makes hard / forecloses:** the MCP servers are security-relevant only insofar as the gateway is
correct. The gateway becomes unambiguously the trust chokepoint, which raises the review bar on
AS-014 specifically. The threat model must state — and does — that a compromised host defeats
this, because nothing below the gateway re-checks authority.

**Cost to be explicit about:** if an MCP server ever becomes remotely reachable, this decision is
immediately invalid. That is the revisit condition below, not a hypothetical.

## Revisit when

Any MCP server gains a network listener, is deployed out of process on another host, or is shared
between more than one gateway instance.
