"""Ed25519 key custody for capability signing (AS-011).

``SecretStr`` is redaction, not key management — it prevents accidental ``repr`` leakage
and nothing else. This module is the actual custody story:

* keys are generated on disk with owner-only permissions;
* every grant carries a ``kid``, so a key can be rotated without invalidating the audit
  trail's ability to say which key signed what;
* verification takes a *set* of public keys, so old and new keys can be trusted
  simultaneously during a rotation;
* the private key never enters the repository, and generation refuses to overwrite.

Ed25519 rather than RSA or HMAC: signatures are 64 bytes, verification is fast enough to
sit in the request path, and — unlike a shared HMAC secret — the verifier does not hold
material that would let it mint. That asymmetry matters here, because the gateway verifies
on every call while only the authorization service should be able to sign.

The threat model states plainly that an attacker holding the private key can mint valid
authority. There is no hardware root of trust in this project.
"""

from __future__ import annotations

import os
import pathlib
import stat
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

#: Owner read/write only. Enforced on POSIX; Windows ACLs are not equivalent and the
#: mismatch is reported rather than silently ignored.
PRIVATE_KEY_MODE: Final = 0o600


class KeyCustodyError(Exception):
    """Raised when a key cannot be loaded or stored safely."""


@dataclass(frozen=True, slots=True)
class SigningKey:
    """A private key with the identity that will appear in every grant it signs."""

    kid: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()


@dataclass(frozen=True, slots=True)
class VerificationKeyring:
    """Public keys trusted for verification, indexed by ``kid``.

    A mapping rather than a single key so that rotation is possible without a flag day:
    grants signed by the outgoing key stay verifiable until they expire, which for a
    30-120 second TTL is a very short window.
    """

    keys: dict[str, Ed25519PublicKey]

    def get(self, kid: str) -> Ed25519PublicKey | None:
        return self.keys.get(kid)

    def __contains__(self, kid: str) -> bool:
        return kid in self.keys

    @classmethod
    def of(cls, kid: str, public_key: Ed25519PublicKey) -> VerificationKeyring:
        return cls(keys={kid: public_key})


def generate_dev_keypair(path: pathlib.Path, *, kid: str = "dev-key-1") -> SigningKey:
    """Generate a development signing key at ``path``.

    Refuses to overwrite an existing key: silently replacing one would invalidate every
    grant in flight and, worse, would do so without anybody noticing until verification
    started failing.
    """
    if path.exists():
        raise KeyCustodyError(
            f"{path} already exists; refusing to overwrite a signing key. "
            "Delete it explicitly if you intend to rotate."
        )

    private_key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Create with restrictive permissions from the outset rather than writing then
    # chmod-ing: the gap between the two is a window in which the key is world-readable.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_KEY_MODE)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)

    return SigningKey(kid=kid, private_key=private_key)


def load_signing_key(path: pathlib.Path, *, kid: str) -> SigningKey:
    """Load a private key, checking its permissions on platforms that have them."""
    if not path.exists():
        raise KeyCustodyError(
            f"signing key not found at {path}. Generate one with "
            "`uv run python -m agentsec.authz.keys --generate`."
        )

    _check_permissions(path)

    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise KeyCustodyError(f"could not parse signing key at {path}") from exc

    if not isinstance(key, Ed25519PrivateKey):
        raise KeyCustodyError(
            f"key at {path} is {type(key).__name__}, expected Ed25519. "
            "Capability grants are Ed25519 only."
        )
    return SigningKey(kid=kid, private_key=key)


def _check_permissions(path: pathlib.Path) -> None:
    """Warn loudly if a private key is readable by anyone but its owner.

    Skipped on Windows, where POSIX mode bits are not meaningful. That limitation is
    reported rather than papered over: a check that silently does nothing on the
    development platform is worse than no check, because it implies a guarantee.
    """
    if os.name != "posix":
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise KeyCustodyError(
            f"signing key at {path} has permissions {mode:o}; expected {PRIVATE_KEY_MODE:o}. "
            "A key readable beyond its owner should be treated as compromised and rotated."
        )


def load_public_key(path: pathlib.Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise KeyCustodyError(f"key at {path} is not an Ed25519 public key")
    return key


def export_public_key(signing_key: SigningKey, path: pathlib.Path) -> None:
    """Write the public half, which is safe to distribute and to commit."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        signing_key.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


__all__ = [
    "PRIVATE_KEY_MODE",
    "KeyCustodyError",
    "SigningKey",
    "VerificationKeyring",
    "export_public_key",
    "generate_dev_keypair",
    "load_public_key",
    "load_signing_key",
]
