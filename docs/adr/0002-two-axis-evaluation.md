# ADR-0002 — Two-axis adversarial evaluation

**Status:** Accepted
**Date:** 2026-08-31
**Issue:** AS-028B, AS-035, AS-038

## Context

The evaluation was originally a single axis: run indirect prompt-injection scenarios against a real
model and measure how often an attack succeeds, comparing progressively stronger control stacks.

That design has a failure mode which would only surface after the corpus was built. Published
results put plain-text indirect injection at roughly 5% attack success on AgentDojo and 15% on
InjecAgent against frontier models. If the corpus is built from hand-written plain-text payloads,
the baseline lands near the floor, every control stack ties, and the ablation demonstrates nothing
— after the expense of building 100+ scenarios and running them.

Template-aware and multi-turn attacks reach roughly 32%/46% and 52% respectively (ChatInject,
ICLR 2026, arXiv 2509.22830), so the single-axis design is salvageable with a stronger corpus. But
it has a second, structural weakness: a security claim resting on frontier-model gullibility has a
shelf life measured in model releases. The same benchmark re-run in a year may show nothing,
without anything about AgentSec having changed.

## Decision

Evaluate on **two independent axes**, reported separately:

- **Axis A — model susceptibility.** A real model against a template-aware, multi-turn injection
  corpus (AS-035). Answers: does a real model, under adversarial context, propose something unsafe?
- **Axis B — control-plane guarantee.** A deterministic `AdversarialPlanner` (AS-028B) emitting the
  attacker's desired `ActionPlan` directly, modelling a planner that is already fully compromised.
  Answers: when the planner is hostile, does anything unsafe actually execute?

The ablation matrix is `2 planners x 5 control stacks = 10 cells`, not a flat list of arms. Both
axes must traverse an identical downstream path; if the adversarial planner reaches the gateway by
a different route, the comparison is meaningless.

## Alternatives considered

**Axis A only, with a stronger corpus.** Rejected: fixes the immediate measurement problem but
leaves the headline claim dependent on model behaviour, which the project does not control and
which changes underneath it.

**Axis B only.** Rejected: it would say nothing about whether the system helps against real model
failure, and the attempts-versus-executions distinction needs real attempts to be interesting.

**Use a deliberately weak model for the baseline.** Rejected: that is strawmanning the baseline,
which the AS-039 frozen-baseline ADR exists specifically to prevent. A result obtained that way is
not credible and a reviewer would say so.

## Consequences

**Makes easy:** Axis B runs in CI with no API key and no cost, so the core guarantee is verified on
every commit rather than once at benchmark time. It also does not decay — "a fully compromised
planner cannot cause an unauthorized execution" stays true across model generations.

**Makes hard:** two axes double the reporting surface, and conflating them in a summary would be
worse than having one. Every report must keep them separate and label which question it answers.

**Cost to be explicit about:** Axis B proves a property of the control plane over a *modelled*
attack set. It is not a proof over an infinite input space. Reports say "zero observed unauthorized
executions across N trials", never "proven zero rate". AS-036 exists precisely because a
well-formed adversarial planner does not exercise parser boundaries.

## Revisit when

Axis A's baseline lands near zero even with a template-aware, multi-turn corpus — in which case
that is a publishable negative result about frontier model robustness, and Axis A's role in the
README changes from headline to supporting evidence.
