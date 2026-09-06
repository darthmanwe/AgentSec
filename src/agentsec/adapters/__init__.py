"""External backend adapters (AS-033).

One member so far: GitHub, the only genuinely external backend in the project and the
reason capability enforcement is gateway-side (ADR-0001). GitHub cannot verify our grants;
it has never heard of them.
"""

from agentsec.adapters.github import (
    CapabilityRequiredError,
    Comment,
    FakeGitHub,
    FileContent,
    GitHubAdapter,
    GitHubError,
    Outcome,
    RepositoryNotAllowedError,
    operation_marker,
    require_allowed,
)

__all__ = [
    "CapabilityRequiredError",
    "Comment",
    "FakeGitHub",
    "FileContent",
    "GitHubAdapter",
    "GitHubError",
    "Outcome",
    "RepositoryNotAllowedError",
    "operation_marker",
    "require_allowed",
]
