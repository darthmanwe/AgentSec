"""A deliberately clean module. Nothing here should be flagged."""

import sqlite3


def find_user(connection: sqlite3.Connection, username: str):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchone()
