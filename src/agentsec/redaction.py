"""Recursive redaction for arbitrary nested data (AS-003).

This is the *only* redaction path for logs and, later, OpenTelemetry attributes
(AS-041). A second implementation would eventually disagree with this one, and the
disagreement would be discovered by finding a secret in a trace.

It complements rather than duplicates ``config.safe_dump``. That one is type-driven: a
field is redacted because it was declared ``SecretStr``. This one is pattern-driven,
because by the time data reaches a log record it is a plain ``dict`` with no types left
to consult. Both are needed; neither subsumes the other.

Design decisions worth stating:

* **No partial reveal.** Not even a prefix or a hash fingerprint. A fingerprint would be
  genuinely useful for correlating "is this the same key as last run", but it also enables
  offline brute-force against low-entropy secrets such as passwords, and the threat model
  says secrets never enter logs.
* **Keys are matched by substring, not equality.** ``x-api-key``, ``API_KEY`` and
  ``anthropic_api_key`` must all match, and enumerating every spelling is how one gets
  missed.
* **Depth and cycle bounded.** A log processor that can recurse forever turns a debugging
  aid into an outage.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

REDACTED: Final = "**REDACTED**"
MAX_DEPTH: Final = 12

#: Substrings which, appearing anywhere in a key, mark its value as sensitive.
SENSITIVE_KEY_PARTS: Final[frozenset[str]] = frozenset(
    {
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "cookie",
        "credential",
        "passwd",
        "password",
        "private_key",
        "secret",
        "session_key",
        "token",
    }
)

#: Keys that contain a sensitive substring but are not themselves secret. Without this,
#: ``token_count`` and ``auth_decision`` would be redacted, which would quietly destroy
#: the usage accounting and authorization audit trail this project depends on.
SENSITIVE_KEY_EXCEPTIONS: Final[frozenset[str]] = frozenset(
    {
        "auth_decision",
        "auth_outcome",
        "auth_reason",
        "authorization_outcome",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
        "credential_type",
        "has_credentials",
        "input_tokens",
        "max_tokens",
        "output_tokens",
        "requires_credentials",
        "token_count",
        "tokens",
        "total_tokens",
    }
)

#: Values recognisably secret regardless of the key they arrived under - a token pasted
#: into a free-text field, or an error message quoting the credential that failed.
SENSITIVE_VALUE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),  # Anthropic
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),  # GitHub classic
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),  # GitHub fine-grained
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),  # PEM private key
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"),  # JWT
    re.compile(r"\bBearer\s+[A-Za-z0-9_\-.=]{12,}", re.IGNORECASE),
)

#: Credentials embedded in a connection URL: scheme://user:password@host. The database URL
#: is exactly this shape, so it is the most likely secret to appear in a log by accident.
_URL_CREDENTIALS: Final = re.compile(
    r"(?P<scheme>[a-zA-Z][\w+.\-]*://)(?P<user>[^:/@\s]+):(?P<pw>[^@/\s]+)@"
)


def _normalise_key(key: str) -> str:
    """Fold case and separator style so one spelling of a name matches all of them.

    HTTP headers use hyphens (``x-api-key``, ``Set-Cookie``) while Python fields use
    underscores (``api_key``). Matching only one style silently lets the other through,
    and headers are the most common place a credential appears.
    """
    return key.lower().replace("-", "_").replace(" ", "_").replace(".", "_")


def is_sensitive_key(key: str) -> bool:
    """Whether a mapping key marks its value as sensitive."""
    normalised = _normalise_key(key)
    if normalised in SENSITIVE_KEY_EXCEPTIONS:
        return False
    return any(part in normalised for part in SENSITIVE_KEY_PARTS)


def redact_text(text: str) -> str:
    """Redact recognisable secrets appearing inside a free-text string.

    Used for messages and exception text, where a credential may be quoted rather than
    passed as a field.
    """
    redacted = _URL_CREDENTIALS.sub(rf"\g<scheme>\g<user>:{REDACTED}@", text)
    for pattern in SENSITIVE_VALUE_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def redact(value: Any, *, _depth: int = 0, _seen: frozenset[int] | None = None) -> Any:
    """Return a redacted copy of ``value``, recursing into mappings and sequences.

    The input is never mutated: log processors run on live application data, and a
    redactor with side effects would corrupt the very state it is reporting on.
    """
    seen = _seen or frozenset()

    if _depth > MAX_DEPTH:
        return "**TRUNCATED:max-depth**"

    # Cycle guard for containers only; scalars cannot recurse.
    if isinstance(value, Mapping | list | tuple | set | frozenset):
        if id(value) in seen:
            return "**TRUNCATED:cycle**"
        seen = seen | {id(value)}

    if isinstance(value, Mapping):
        return {
            key: REDACTED
            if isinstance(key, str) and is_sensitive_key(key)
            else redact(item, _depth=_depth + 1, _seen=seen)
            for key, item in value.items()
        }

    if isinstance(value, str):
        return redact_text(value)

    if isinstance(value, bytes):
        return value  # opaque; never rendered into a log line as-is

    # str is a Sequence, so it must be handled above this branch.
    if isinstance(value, list | tuple | set | frozenset):
        items = [redact(item, _depth=_depth + 1, _seen=seen) for item in value]
        if isinstance(value, tuple):
            return tuple(items)
        if isinstance(value, set | frozenset):
            # A redacted set may collapse duplicates; a list keeps the original cardinality
            # visible, which matters when counting redacted entries.
            return items
        return items

    # Anything exposing get_secret_value is a pydantic SecretStr or equivalent.
    if hasattr(value, "get_secret_value"):
        return REDACTED

    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [redact(item, _depth=_depth + 1, _seen=seen) for item in value]

    return value


__all__ = [
    "MAX_DEPTH",
    "REDACTED",
    "SENSITIVE_KEY_EXCEPTIONS",
    "SENSITIVE_KEY_PARTS",
    "SENSITIVE_VALUE_PATTERNS",
    "is_sensitive_key",
    "redact",
    "redact_text",
]
