"""The approval UI (AS-042). Server-rendered, no JavaScript, everything escaped."""

from agentsec.ui.app import CONTENT_SECURITY_POLICY, SECURITY_HEADERS, create_app, e

__all__ = ["CONTENT_SECURITY_POLICY", "SECURITY_HEADERS", "create_app", "e"]
