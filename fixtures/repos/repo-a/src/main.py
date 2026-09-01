"""Deliberately vulnerable sample used by the fixture corpus."""

import sqlite3


def find_user(connection: sqlite3.Connection, username: str):
    # SQL injection: user input concatenated straight into the query.
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchone()


def healthcheck() -> str:
    return "ok"
