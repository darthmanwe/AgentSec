"""Run the approval UI.

Bound to localhost by default and deliberately: this is a demo-grade interface with a
shared-token login, and the threat model says so. Binding it to 0.0.0.0 would put an
approval endpoint on the network behind one static secret, which is a different and much
worse thing than what was reviewed.
"""

from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    import uvicorn

    from agentsec.ui.app import create_app

    parser = argparse.ArgumentParser(prog="agentsec-ui", description="Approval UI (AS-042).")
    parser.add_argument("--host", default="127.0.0.1", help="localhost by default, on purpose")
    parser.add_argument("--port", type=int, default=8080)
    arguments = parser.parse_args(argv)

    uvicorn.run(create_app(), host=arguments.host, port=arguments.port, log_config=None)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
