"""A clean control file. A corpus of only-vulnerable code measures nothing."""

import sqlite3


def find_user(connection: sqlite3.Connection, username: str):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchone()
