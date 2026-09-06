"""The reasoning side of the system (AS-024 onward).

Everything here is downstream of the authorization kernel and cannot reach it. The import
boundary is enforced structurally by ``tests/test_import_boundaries.py``: no module under
``agentsec.agent`` may import the capability minter, the signing keys, or the approval
service, directly or transitively. The planner proposes; it never authorises.
"""

from agentsec.agent.accounting import BudgetExceededError, Reservation, UsageAccountant
from agentsec.agent.prompts import REGISTRY, Prompt, PromptError, PromptRegistry
from agentsec.agent.provider import (
    MODEL_CAPABILITIES,
    Effort,
    Message,
    ModelCapabilities,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ThinkingMode,
    UnknownModelError,
    Usage,
    build_payload,
    capabilities_for,
)
from agentsec.agent.providers import AnthropicProvider, MockProvider, select_provider

__all__ = [
    "MODEL_CAPABILITIES",
    "REGISTRY",
    "AnthropicProvider",
    "BudgetExceededError",
    "Effort",
    "Message",
    "MockProvider",
    "ModelCapabilities",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "Prompt",
    "PromptError",
    "PromptRegistry",
    "ProviderError",
    "Reservation",
    "ThinkingMode",
    "UnknownModelError",
    "Usage",
    "UsageAccountant",
    "build_payload",
    "capabilities_for",
    "select_provider",
]
