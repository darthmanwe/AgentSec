"""The reasoning side of the system (AS-024 onward).

Everything here is downstream of the authorization kernel and cannot reach it. The import
boundary is enforced structurally by ``tests/test_import_boundaries.py``: no module under
``agentsec.agent`` may import the capability minter, the signing keys, or the approval
service, directly or transitively. The planner proposes; it never authorises.
"""

from agentsec.agent.accounting import BudgetExceededError, Reservation, UsageAccountant
from agentsec.agent.adversarial import SCENARIOS, AdversarialPlanner, AttackGoal, AttackScenario
from agentsec.agent.planner import ACTION_PLAN_SCHEMA, BoundedPlanner, PlanningResult
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
from agentsec.agent.state import Hypothesis, ProposedAction, SecurityAgentState, StateError

__all__ = [
    "ACTION_PLAN_SCHEMA",
    "MODEL_CAPABILITIES",
    "REGISTRY",
    "SCENARIOS",
    "AdversarialPlanner",
    "AnthropicProvider",
    "AttackGoal",
    "AttackScenario",
    "BoundedPlanner",
    "BudgetExceededError",
    "Effort",
    "Hypothesis",
    "Message",
    "MockProvider",
    "ModelCapabilities",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "PlanningResult",
    "Prompt",
    "PromptError",
    "PromptRegistry",
    "ProposedAction",
    "ProviderError",
    "Reservation",
    "SecurityAgentState",
    "StateError",
    "ThinkingMode",
    "UnknownModelError",
    "Usage",
    "UsageAccountant",
    "build_payload",
    "capabilities_for",
    "select_provider",
]
