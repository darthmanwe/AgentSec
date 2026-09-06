"""Operator command line (AS-021).

The human end of the human-in-the-loop control. Without it, S2 promises an
approval-gated demo that cannot actually be driven — the original package had no way to
approve anything until the UI in AS-042, which is very late to discover that the gate has
never been operated by a person.

AS-042's UI consumes this rather than replacing it, so there is exactly one path through
which a decision is recorded.
"""

from agentsec.cli.main import main

__all__ = ["main"]
