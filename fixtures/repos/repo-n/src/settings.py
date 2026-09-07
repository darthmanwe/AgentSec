import os


def database_url() -> str:
    return os.environ["DATABASE_URL"]
