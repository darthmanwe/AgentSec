"""Data access, written the way it should be."""

import hashlib
import sqlite3
import subprocess


def find_user(connection: sqlite3.Connection, username: str):
    cursor = connection.cursor()
    cursor.execute("SELECT id, name FROM users WHERE name = ?", (username,))
    return cursor.fetchone()


def checksum(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def run_migration(script: str) -> int:
    return subprocess.run(["./migrate", script], check=False).returncode
