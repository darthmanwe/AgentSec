"""Loads configuration and cached objects."""

import hashlib
import pickle

import yaml


def load_config(text: str):
    # Unsafe: constructs arbitrary Python objects from the document.
    return yaml.load(text)


def load_cache(blob: bytes):
    # Unpickling untrusted data executes arbitrary code.
    return pickle.loads(blob)


def fingerprint(value: str) -> str:
    # MD5 is broken for any security purpose.
    return hashlib.md5(value.encode()).hexdigest()
