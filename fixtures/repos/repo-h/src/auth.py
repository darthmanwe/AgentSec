"""Authentication helpers.

Deliberately full of words a naive scanner might react to - password, secret, token,
credential - with nothing actually wrong. A rule that fires here is a false positive.
"""

import hashlib
import hmac
import os


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex()


def verify_token(presented: str, expected: str) -> bool:
    return hmac.compare_digest(presented, expected)


def load_secret() -> str | None:
    return os.environ.get("SERVICE_SECRET")
