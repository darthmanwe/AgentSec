# Architecture Decision Records

One file per decision, numbered sequentially, never deleted. A decision that turns out wrong gets
a new ADR that supersedes the old one; the original stays so the reasoning trail survives.

The master prompt instructs recording an ADR when an architectural conflict is hit, rather than
inventing a second architecture around it. That only works if this directory exists from the
start, so it is created in AS-001.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-gateway-only-capability-enforcement.md) | Gateway-only capability enforcement | Accepted |
| [0002](0002-two-axis-evaluation.md) | Two-axis adversarial evaluation | Accepted |

## Template

Copy [`0000-template.md`](0000-template.md).
