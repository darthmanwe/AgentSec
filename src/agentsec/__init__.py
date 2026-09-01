"""AgentSec: a policy-governed runtime for an LLM security agent.

The architectural invariant this package exists to enforce:

    The LLM may reason, propose actions, and request capabilities. It must never
    authorize itself, mint authority, or directly execute consequential external
    side effects.

See ``docs/THREAT_MODEL.md`` for the trust boundaries and adversary model.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
