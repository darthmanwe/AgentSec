# Portfolio Rationale

AgentSec should add a new hiring signal rather than duplicate existing GraphRAG, memory, or distributed-training work.

The intended reviewer takeaway is:

> This engineer can put deterministic security, reliability, and audit boundaries around a probabilistic agent that uses real tools.

The project should visibly prove:
- model mistakes can be tolerated without becoming unsafe backend effects;
- authorization is outside the model;
- approval binds to exact action arguments;
- retries do not duplicate writes;
- malicious context remains data, not authority;
- security controls are evaluated for both safety and utility cost;
- failures are published, not hidden.

The headline distinction to preserve in all reports is:

**unauthorized action attempts != unauthorized action executions**

The model may propose unsafe actions under adversarial pressure. A strong system demonstrates that those attempts are blocked before backend execution.
