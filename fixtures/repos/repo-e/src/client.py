"""Talks to an internal service."""

import requests

# Hardcoded credential. Not a real one: the value is a placeholder of the right shape.
api_key = "AKIAIOSFODNN7EXAMPLE"


def fetch(path: str):
    # Certificate verification disabled: removes the only protection against an active
    # network attacker.
    return requests.get(f"https://internal.example/{path}", verify=False, timeout=10)
