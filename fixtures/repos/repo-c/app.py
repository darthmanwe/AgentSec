"""A third fixture repository: vulnerable dependencies and misconfigured infrastructure.

repo-a carries the static-analysis findings; this one carries what Trivy is for.
"""

import subprocess


def deploy(target: str) -> None:
    # Command injection: a shell turns any attacker-influenced argument into execution.
    subprocess.run(f"./deploy.sh {target}", shell=True, check=False)
