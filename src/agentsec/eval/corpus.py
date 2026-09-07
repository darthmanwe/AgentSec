"""The offline benchmark corpus (AS-034).

Repositories and their ground truth are declared together in one place and *generated*
from that declaration. The alternative — writing vulnerable files by hand and maintaining
a separate answer key — drifts on the first edit, and a benchmark whose answer key is
subtly wrong is worse than no benchmark, because it produces confident numbers.

Three properties the generator enforces:

**Ground truth is not readable from inside a repository.** It is written to
``fixtures/ground_truth/``, a sibling of ``fixtures/repos/``. The fixture MCP server is
rooted at an individual repository and refuses traversal, so an agent under evaluation
cannot read its own answer key. That is not paranoia about the model; it is what makes a
score mean something.

**Finding ids are stable.** ``repo-d/py-sqli-1`` identifies the same seeded vulnerability
across every run and every regeneration, so results are comparable over time. Ids derived
from line numbers would change whenever a file was edited.

**Clean controls are part of the corpus, not an afterthought.** A scanner that flags
everything scores perfect recall. Repositories with no seeded findings are what make the
false-positive rate measurable, and roughly a third of the corpus is deliberately clean.

No real secrets appear anywhere. Every credential-shaped string is a syntactically valid
but non-functional placeholder, and the manifest records that.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from dataclasses import dataclass, field
from typing import Any, Final

CORPUS_VERSION: Final = "1.0.0"
CORPUS_DOMAIN: Final = "agentsec.corpus.v1"

REPO_ROOT: Final = pathlib.Path(__file__).resolve().parents[3]
REPOS_DIR: Final = REPO_ROOT / "fixtures" / "repos"
GROUND_TRUTH_DIR: Final = REPO_ROOT / "fixtures" / "ground_truth"


@dataclass(frozen=True, slots=True)
class SeededFinding:
    """One vulnerability deliberately placed in the corpus.

    ``rule`` names the first-party Semgrep rule expected to fire, or the CVE Trivy should
    report. Stating the expected detector makes a miss diagnosable: "recall is 0.8" says
    nothing, "the traversal rule never fires" says where to look.
    """

    id: str
    rule: str
    path: str
    cwe: str
    severity: str = "high"
    detector: str = "semgrep"

    def __post_init__(self) -> None:
        if "/" not in self.id:
            raise ValueError(f"finding id {self.id!r} must be repo-scoped")


@dataclass(frozen=True, slots=True)
class FixtureRepo:
    """One repository in the corpus."""

    name: str
    language: str
    description: str
    files: dict[str, str]
    findings: tuple[SeededFinding, ...] = ()

    @property
    def is_clean(self) -> bool:
        """A control repository. These make the false-positive rate measurable; a scanner
        that flags everything scores perfect recall without them."""
        return not self.findings

    def digest(self) -> str:
        """Content hash, line endings normalised.

        The same normalisation the execution-package manifest needed: a corpus hash that
        changes because a file was checked out on Windows tells you nothing about the
        corpus.
        """
        material = CORPUS_DOMAIN + "\n" + self.name + "\n"
        for path in sorted(self.files):
            body = self.files[path].replace("\r\n", "\n")
            material += f"{path}\n{hashlib.sha256(body.encode()).hexdigest()}\n"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _py(body: str) -> str:
    return body.lstrip("\n")


# --------------------------------------------------------------------------- the corpus

REPOS: Final[tuple[FixtureRepo, ...]] = (
    FixtureRepo(
        name="repo-a",
        language="python",
        description="A small service with a classic SQL injection.",
        files={
            "README.md": "# repo-a\n\nA sample service used by the AgentSec fixture corpus.\n",
            "docs/notes.md": "Internal notes. Nothing sensitive here.\n",
            "src/main.py": _py("""
\"\"\"Deliberately vulnerable sample used by the fixture corpus.\"\"\"

import sqlite3


def find_user(connection: sqlite3.Connection, username: str):
    # SQL injection: user input concatenated straight into the query.
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchone()


def healthcheck() -> str:
    return "ok"
"""),
            "src/safe.py": _py("""
\"\"\"A deliberately clean module. Nothing here should be flagged.\"\"\"

import sqlite3


def find_user(connection: sqlite3.Connection, username: str):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchone()
"""),
        },
        findings=(
            SeededFinding(
                id="repo-a/py-sqli-1",
                rule="agentsec.python.sql-injection-concat",
                path="src/main.py",
                cwe="CWE-89",
            ),
        ),
    ),
    FixtureRepo(
        name="repo-b",
        language="python",
        description="A second repository, used to prove assignment scoping.",
        files={
            "app/handler.py": _py("""
\"\"\"A second fixture repository, used to prove assignment scoping.

A server assigned to repo-a must not be able to read this file.
\"\"\"

SECRET_MARKER = "repo-b-should-not-be-readable-from-repo-a"
"""),
            "README.md": "# repo-b\n\nOut of scope for a run assigned to repo-a.\n",
        },
    ),
    FixtureRepo(
        name="repo-c",
        language="python",
        description="Vulnerable dependencies and misconfigured infrastructure.",
        files={
            "requirements.txt": _py("""
# Deliberately vulnerable pinned dependencies, used as scanner ground truth (AS-030).
# Every version here is old enough to carry published advisories; they exist so the
# evaluation has a known denominator, not because anything installs them.
PyYAML==5.3.1
requests==2.19.1
urllib3==1.24.1
Jinja2==2.10
"""),
            "app.py": _py("""
\"\"\"A third fixture repository: vulnerable dependencies and misconfigured infrastructure.

repo-a carries the static-analysis findings; this one carries what Trivy is for.
\"\"\"

import subprocess


def deploy(target: str) -> None:
    # Command injection: a shell turns any attacker-influenced argument into execution.
    subprocess.run(f"./deploy.sh {target}", shell=True, check=False)
"""),
            "infra/Dockerfile": _py("""
# Deliberately misconfigured, used as IaC scanner ground truth (AS-030).
FROM ubuntu:20.04

# Runs as root: no USER instruction anywhere in this file.
RUN apt-get update && apt-get install -y curl

# A secret baked into an image layer, where it survives every later deletion.
ENV API_KEY="sk-live-not-a-real-key-000000000000"

COPY . /app
EXPOSE 22
CMD ["/app/run.sh"]
"""),
        },
        findings=(
            SeededFinding(
                id="repo-c/py-shell-1",
                rule="agentsec.python.subprocess-shell-true",
                path="app.py",
                cwe="CWE-78",
            ),
            SeededFinding(
                id="repo-c/dep-pyyaml",
                rule="CVE-2020-14343",
                path="requirements.txt",
                cwe="CWE-502",
                detector="trivy",
            ),
            SeededFinding(
                id="repo-c/iac-root-user",
                rule="DS-0002",
                path="infra/Dockerfile",
                cwe="CWE-250",
                detector="trivy",
            ),
        ),
    ),
    FixtureRepo(
        name="repo-d",
        language="python",
        description="Deserialisation and weak cryptography.",
        files={
            "README.md": "# repo-d\n\nLegacy import pipeline.\n",
            "src/loader.py": _py("""
\"\"\"Loads configuration and cached objects.\"\"\"

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
"""),
        },
        findings=(
            SeededFinding(
                id="repo-d/py-yaml-1",
                rule="agentsec.python.yaml-unsafe-load",
                path="src/loader.py",
                cwe="CWE-502",
            ),
            SeededFinding(
                id="repo-d/py-pickle-1",
                rule="agentsec.python.pickle-load",
                path="src/loader.py",
                cwe="CWE-502",
            ),
            SeededFinding(
                id="repo-d/py-md5-1",
                rule="agentsec.python.insecure-hash",
                path="src/loader.py",
                cwe="CWE-327",
                severity="medium",
            ),
        ),
    ),
    FixtureRepo(
        name="repo-e",
        language="python",
        description="Hardcoded credentials and disabled TLS verification.",
        files={
            "src/client.py": _py("""
\"\"\"Talks to an internal service.\"\"\"

import requests

# Hardcoded credential. Not a real one: the value is a placeholder of the right shape.
api_key = "AKIAIOSFODNN7EXAMPLE"


def fetch(path: str):
    # Certificate verification disabled: removes the only protection against an active
    # network attacker.
    return requests.get(f"https://internal.example/{path}", verify=False, timeout=10)
"""),
        },
        findings=(
            SeededFinding(
                id="repo-e/py-credential-1",
                rule="agentsec.python.hardcoded-credential",
                path="src/client.py",
                cwe="CWE-798",
                severity="medium",
            ),
            SeededFinding(
                id="repo-e/py-tls-1",
                rule="agentsec.python.disabled-tls-verification",
                path="src/client.py",
                cwe="CWE-295",
            ),
        ),
    ),
    FixtureRepo(
        name="repo-f",
        language="python",
        description="Dynamic evaluation of caller-supplied input.",
        files={
            "src/rules.py": _py("""
\"\"\"Evaluates user-authored rule expressions.\"\"\"


def apply_rule(expression: str, context: dict):
    # Arbitrary code execution wherever the expression can be influenced.
    return eval(expression)
"""),
        },
        findings=(
            SeededFinding(
                id="repo-f/py-eval-1",
                rule="agentsec.python.eval-of-input",
                path="src/rules.py",
                cwe="CWE-95",
            ),
        ),
    ),
    FixtureRepo(
        name="repo-g",
        language="python",
        description="Clean control: idiomatic, parameterised, no findings expected.",
        files={
            "README.md": "# repo-g\n\nA well-maintained service.\n",
            "src/repository.py": _py("""
\"\"\"Data access, written the way it should be.\"\"\"

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
"""),
        },
    ),
    FixtureRepo(
        name="repo-h",
        language="python",
        description="Clean control with security-adjacent vocabulary but no defects.",
        files={
            "src/auth.py": _py("""
\"\"\"Authentication helpers.

Deliberately full of words a naive scanner might react to - password, secret, token,
credential - with nothing actually wrong. A rule that fires here is a false positive.
\"\"\"

import hashlib
import hmac
import os


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex()


def verify_token(presented: str, expected: str) -> bool:
    return hmac.compare_digest(presented, expected)


def load_secret() -> str | None:
    return os.environ.get("SERVICE_SECRET")
"""),
        },
    ),
    FixtureRepo(
        name="repo-i",
        language="typescript",
        description="Command injection and prototype-pollution shaped code.",
        files={
            "package.json": json.dumps(
                {"name": "repo-i", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
                indent=2,
            )
            + "\n",
            "src/deploy.ts": _py("""
import { execSync } from "child_process";

export function deploy(target: string): string {
  // Command injection: the argument is interpolated into a shell string.
  return execSync(`./deploy.sh ${target}`).toString();
}
"""),
        },
        findings=(
            SeededFinding(
                id="repo-i/ts-command-injection-1",
                rule="agentsec.typescript.command-injection",
                path="src/deploy.ts",
                cwe="CWE-78",
            ),
            SeededFinding(
                id="repo-i/dep-lodash",
                rule="CVE-2020-8203",
                path="package.json",
                cwe="CWE-1321",
                detector="trivy",
            ),
        ),
    ),
    FixtureRepo(
        name="repo-j",
        language="typescript",
        description="Clean TypeScript control.",
        files={
            "package.json": json.dumps(
                {"name": "repo-j", "version": "2.1.0", "dependencies": {}}, indent=2
            )
            + "\n",
            "src/index.ts": _py("""
export function greet(name: string): string {
  return `hello, ${name}`;
}
"""),
        },
    ),
    FixtureRepo(
        name="repo-k",
        language="go",
        description="Path traversal in a file server.",
        files={
            "go.mod": "module example.com/repo-k\n\ngo 1.22\n",
            "main.go": _py("""
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

// Path traversal: the request path is joined without being contained.
func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, err := os.ReadFile(filepath.Join("/var/data", name))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}
"""),
        },
        findings=(
            SeededFinding(
                id="repo-k/go-traversal-1",
                rule="agentsec.go.path-traversal",
                path="main.go",
                cwe="CWE-22",
            ),
        ),
    ),
    FixtureRepo(
        name="repo-l",
        language="go",
        description="Clean Go control.",
        files={
            "go.mod": "module example.com/repo-l\n\ngo 1.22\n",
            "main.go": _py("""
package main

import "fmt"

func main() {
	fmt.Println("ok")
}
"""),
        },
    ),
    FixtureRepo(
        name="repo-m",
        language="yaml",
        description="Kubernetes and Terraform misconfiguration.",
        files={
            "k8s/deployment.yaml": _py("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: api
          image: example/api:latest
          securityContext:
            privileged: true
            runAsUser: 0
"""),
            "terraform/main.tf": _py("""
resource "aws_s3_bucket" "public" {
  bucket = "agentsec-fixture-bucket"
  acl    = "public-read"
}

resource "aws_security_group_rule" "open_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
"""),
        },
        findings=(
            SeededFinding(
                id="repo-m/k8s-privileged",
                rule="KSV017",
                path="k8s/deployment.yaml",
                cwe="CWE-250",
                detector="trivy",
            ),
            SeededFinding(
                id="repo-m/tf-open-ssh",
                rule="AVD-AWS-0107",
                path="terraform/main.tf",
                cwe="CWE-284",
                detector="trivy",
            ),
        ),
    ),
    FixtureRepo(
        name="repo-n",
        language="python",
        description="Clean control containing a file named like a secret but holding none.",
        files={
            "README.md": "# repo-n\n\nConfiguration examples only.\n",
            "config/example.env.template": _py("""
# Template only. Values are placeholders; nothing here is a credential.
DATABASE_URL=postgresql://user:CHANGE_ME@localhost:5432/app
API_KEY=CHANGE_ME
"""),
            "src/settings.py": _py("""
import os


def database_url() -> str:
    return os.environ["DATABASE_URL"]
"""),
        },
    ),
)


# --------------------------------------------------------------------------- generation


@dataclass
class CorpusManifest:
    """Everything needed to say which corpus a result came from."""

    version: str = CORPUS_VERSION
    repos: dict[str, str] = field(default_factory=dict)
    finding_count: int = 0
    clean_repo_count: int = 0

    @property
    def hash(self) -> str:
        material = CORPUS_DOMAIN + "\n" + self.version + "\n"
        material += "\n".join(f"{name}:{digest}" for name, digest in sorted(self.repos.items()))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def as_document(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "hash": self.hash,
            "repo_count": len(self.repos),
            "clean_repo_count": self.clean_repo_count,
            "finding_count": self.finding_count,
            "repos": dict(sorted(self.repos.items())),
        }


def build_manifest(repos: tuple[FixtureRepo, ...] = REPOS) -> CorpusManifest:
    return CorpusManifest(
        repos={repo.name: repo.digest() for repo in repos},
        finding_count=sum(len(repo.findings) for repo in repos),
        clean_repo_count=sum(1 for repo in repos if repo.is_clean),
    )


def ground_truth(repos: tuple[FixtureRepo, ...] = REPOS) -> dict[str, list[dict[str, Any]]]:
    """The answer key, keyed by repository."""
    return {
        repo.name: [
            {
                "id": finding.id,
                "rule": finding.rule,
                "path": finding.path,
                "cwe": finding.cwe,
                "severity": finding.severity,
                "detector": finding.detector,
            }
            for finding in repo.findings
        ]
        for repo in repos
    }


def all_finding_ids(repos: tuple[FixtureRepo, ...] = REPOS) -> tuple[str, ...]:
    return tuple(sorted(f.id for repo in repos for f in repo.findings))


def generate(
    repos: tuple[FixtureRepo, ...] = REPOS,
    *,
    repos_dir: pathlib.Path = REPOS_DIR,
    truth_dir: pathlib.Path = GROUND_TRUTH_DIR,
) -> CorpusManifest:
    """Write the corpus and its answer key to disk.

    The answer key goes to a *sibling* directory, never inside a repository. The fixture
    MCP server is rooted at an individual repository and refuses traversal, so an agent
    under evaluation cannot read the answers to its own exam.
    """
    for repo in repos:
        base = repos_dir / repo.name
        for relative, content in repo.files.items():
            target = base / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")

    manifest = build_manifest(repos)
    truth_dir.mkdir(parents=True, exist_ok=True)
    (truth_dir / "findings.json").write_text(
        json.dumps(ground_truth(repos), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (truth_dir / "manifest.json").write_text(
        json.dumps(manifest.as_document(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def load_ground_truth(truth_dir: pathlib.Path = GROUND_TRUTH_DIR) -> dict[str, Any]:
    path = truth_dir / "findings.json"
    if not path.exists():
        raise FileNotFoundError(f"ground truth not generated; run the corpus generator ({path})")
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return document


__all__ = [
    "CORPUS_DOMAIN",
    "CORPUS_VERSION",
    "GROUND_TRUTH_DIR",
    "REPOS",
    "REPOS_DIR",
    "CorpusManifest",
    "FixtureRepo",
    "SeededFinding",
    "all_finding_ids",
    "build_manifest",
    "generate",
    "ground_truth",
    "load_ground_truth",
]
