"""A second fixture repository, used to prove assignment scoping.

A server assigned to repo-a must not be able to read this file.
"""

SECRET_MARKER = "repo-b-should-not-be-readable-from-repo-a"
