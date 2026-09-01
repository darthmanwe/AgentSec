"""Validate and regenerate the AgentSec execution package.

The package under ``docs/execution-package`` is the authoritative backlog. The issue
files are the source of truth; every derived artifact (CSV, summary, dependency graph,
manifest) is generated from them, so the two can never drift apart.

    uv run task validate-package          # check
    python scripts/validate_package.py --regenerate

Checks performed:
  * every manifest path exists and its SHA-256 matches
  * every declared dependency resolves to a real issue
  * the dependency graph is acyclic
  * the execution order is a valid topological order of that graph
  * the issue count matches the CSV and the canonical order
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = REPO_ROOT / "docs" / "execution-package"
ISSUES = PACKAGE / "issues"

# DFS colours for the cycle check.
_WHITE, _GREY, _BLACK = 0, 1, 2

# The canonical execution order. This list is the authority on sequencing; the
# dependency graph is the authority on legality. A change here that violates the
# graph is rejected by check_order().
ORDER: list[str] = [
    # S0 - Ground rules
    "AS-000",
    "AS-001",
    "AS-002",
    "AS-003",
    "AS-004",
    "AS-005",
    # S1 - Authorization kernel
    "AS-006",
    "AS-007",
    "AS-008",
    "AS-009",
    "AS-010",
    "AS-011",
    "AS-012",
    # S2 - Governed tool execution
    "AS-013",
    "AS-014",
    "AS-015",
    "AS-016",
    "AS-017",
    "AS-018",
    "AS-019",
    "AS-020",
    "AS-021",
    "AS-022",
    "AS-023",
    "AS-031A",
    "AS-029",
    "AS-030",
    "AS-031B",
    "AS-032",
    "AS-033",
    # S3 - Agent and adversarial evaluation
    "AS-024",
    "AS-027",
    "AS-025",
    "AS-026",
    "AS-028",
    "AS-028B",
    "AS-034",
    "AS-035",
    "AS-036",
    "AS-037",
    "AS-039",
    "AS-038",
    "AS-040",
    # S4 - Observability and release
    "AS-041",
    "AS-042",
]

SLICES: list[tuple[str, str]] = [
    ("S0", "Ground rules"),
    ("S1", "Authorization kernel"),
    ("S2", "Governed tool execution"),
    ("S3", "Agent and adversarial evaluation"),
    ("S4", "Observability and release"),
]

SLICE_OF: dict[str, str] = {}
for _issue in ORDER:
    if _issue == "AS-000":
        _cur = "S0"
    elif _issue == "AS-006":
        _cur = "S1"
    elif _issue == "AS-013":
        _cur = "S2"
    elif _issue == "AS-024":
        _cur = "S3"
    elif _issue == "AS-041":
        _cur = "S4"
    SLICE_OF[_issue] = _cur


class Issue:
    __slots__ = ("deps", "id", "milestone", "path", "title")

    def __init__(
        self, issue_id: str, title: str, milestone: str, deps: list[str], path: pathlib.Path
    ):
        self.id = issue_id
        self.title = title
        self.milestone = milestone
        self.deps = deps
        self.path = path


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_issue(path: pathlib.Path) -> Issue:
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^# (AS-\d{3}[A-Z]?) [—-] (.+?)\s*$", text.split("\n", 1)[0])
    if not m:
        raise ValueError(f"{path.name}: first line is not a well-formed issue header")
    issue_id, title = m.group(1), m.group(2)

    ms = re.search(r"^\*\*Milestone:\*\*\s*(.+?)\s*$", text, re.M)
    if not ms:
        raise ValueError(f"{path.name}: missing Milestone line")
    milestone = ms.group(1).strip()

    ds = re.search(r"^\*\*Dependencies:\*\*\s*(.+?)\s*$", text, re.M)
    if not ds:
        raise ValueError(f"{path.name}: missing Dependencies line")
    raw = ds.group(1).strip()
    deps = [] if raw.lower() in {"none", "-", "—"} else re.findall(r"AS-\d{3}[A-Z]?", raw)
    return Issue(issue_id, title, milestone, deps, path)


def load_issues() -> dict[str, Issue]:
    issues: dict[str, Issue] = {}
    for path in sorted(ISSUES.glob("AS-*.md")):
        issue = parse_issue(path)
        if issue.id in issues:
            raise ValueError(f"duplicate issue id {issue.id}")
        issues[issue.id] = issue
    return issues


# --------------------------------------------------------------------------- checks


def check_deps(issues: dict[str, Issue], errors: list[str]) -> None:
    for issue in issues.values():
        for dep in issue.deps:
            if dep not in issues:
                errors.append(f"{issue.id}: dependency {dep} does not exist")
            if dep == issue.id:
                errors.append(f"{issue.id}: depends on itself")


def check_acyclic(issues: dict[str, Issue], errors: list[str]) -> None:
    colour = dict.fromkeys(issues, _WHITE)

    def visit(node: str, stack: list[str]) -> None:
        colour[node] = _GREY
        for dep in issues[node].deps:
            if dep not in issues:
                continue
            if colour[dep] == _GREY:
                cycle = (
                    " -> ".join([*stack[stack.index(dep) :], dep])
                    if dep in stack
                    else f"{node} -> {dep}"
                )
                errors.append(f"dependency cycle: {cycle}")
            elif colour[dep] == _WHITE:
                visit(dep, [*stack, dep])
        colour[node] = _BLACK

    for node in issues:
        if colour[node] == _WHITE:
            visit(node, [node])


def check_order(issues: dict[str, Issue], errors: list[str]) -> None:
    missing = sorted(set(issues) - set(ORDER))
    extra = sorted(set(ORDER) - set(issues))
    if missing:
        errors.append(f"issues absent from ORDER: {', '.join(missing)}")
    if extra:
        errors.append(f"ORDER names non-existent issues: {', '.join(extra)}")
    position = {issue_id: i for i, issue_id in enumerate(ORDER)}
    for issue in issues.values():
        if issue.id not in position:
            continue
        for dep in issue.deps:
            if dep in position and position[dep] > position[issue.id]:
                errors.append(
                    f"{issue.id} is scheduled before its dependency {dep} "
                    f"(positions {position[issue.id]} < {position[dep]})"
                )


def check_manifest(errors: list[str]) -> None:
    manifest_path = PACKAGE / "MANIFEST.json"
    if not manifest_path.exists():
        errors.append("MANIFEST.json missing")
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for rel, expected in manifest.items():
        path = PACKAGE / rel
        if not path.exists():
            errors.append(f"manifest references missing file: {rel}")
            continue
        actual = sha256(path)
        if actual != expected:
            errors.append(f"hash mismatch: {rel}")
    tracked = set(manifest)
    on_disk = {
        str(p.relative_to(PACKAGE)).replace("\\", "/")
        for p in PACKAGE.rglob("*")
        if p.is_file() and p.name != "MANIFEST.json"
    }
    for rel in sorted(on_disk - tracked):
        errors.append(f"file not in manifest: {rel}")


def check_csv(issues: dict[str, Issue], errors: list[str]) -> None:
    csv_path = PACKAGE / "ISSUE_BACKLOG.csv"
    if not csv_path.exists():
        errors.append("ISSUE_BACKLOG.csv missing")
        return
    with csv_path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    if len(rows) != len(issues):
        errors.append(f"CSV has {len(rows)} rows but there are {len(issues)} issue files")
    for row in rows:
        if row["Issue"] not in issues:
            errors.append(f"CSV names unknown issue {row['Issue']}")


# ---------------------------------------------------------------------- regeneration


def build_csv(issues: dict[str, Issue]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["Order", "Issue", "Title", "Slice", "Milestone", "Dependencies", "File"])
    for i, issue_id in enumerate(ORDER, start=1):
        issue = issues[issue_id]
        writer.writerow(
            [
                i,
                issue.id,
                issue.title,
                SLICE_OF[issue.id],
                issue.milestone,
                " ".join(issue.deps),
                f"issues/{issue.path.name}",
            ]
        )
    return buf.getvalue()


def build_summary(issues: dict[str, Issue]) -> str:
    out = [
        "# AgentSec Backlog Summary",
        "",
        f"{len(ORDER)} issues, grouped into shippable slices. The issue files are the source of",
        "truth; this table is generated by `scripts/validate_package.py --regenerate`.",
        "",
        "| # | Slice | Issue | Title | Dependencies |",
        "|---:|---|---|---|---|",
    ]
    for i, issue_id in enumerate(ORDER, start=1):
        issue = issues[issue_id]
        deps = ", ".join(issue.deps) if issue.deps else "—"
        out.append(f"| {i} | {SLICE_OF[issue_id]} | `{issue.id}` | {issue.title} | {deps} |")
    out.append("")
    return "\n".join(out)


def build_graph(issues: dict[str, Issue]) -> str:
    out = [
        "# Issue Dependency Graph",
        "",
        "Generated by `scripts/validate_package.py --regenerate`. The execution order in",
        "`ISSUE_BACKLOG.csv` is verified to be a topological order of this graph.",
        "",
        "```mermaid",
        "graph TD",
    ]
    for issue_id in ORDER:
        node = issue_id.replace("-", "")
        out.append(f'    {node}["{issue_id}"]')
    for issue_id in ORDER:
        for dep in issues[issue_id].deps:
            out.append(f"    {dep.replace('-', '')} --> {issue_id.replace('-', '')}")
    out.append("```")
    out.append("")
    return "\n".join(out)


def build_manifest() -> str:
    manifest = {}
    for path in sorted(PACKAGE.rglob("*")):
        if path.is_file() and path.name != "MANIFEST.json":
            rel = str(path.relative_to(PACKAGE)).replace("\\", "/")
            manifest[rel] = sha256(path)
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def regenerate(issues: dict[str, Issue]) -> None:
    (PACKAGE / "ISSUE_BACKLOG.csv").write_text(build_csv(issues), encoding="utf-8")
    (PACKAGE / "BACKLOG_SUMMARY.md").write_text(build_summary(issues), encoding="utf-8")
    (PACKAGE / "DEPENDENCY_GRAPH.md").write_text(build_graph(issues), encoding="utf-8")
    # manifest last: it hashes everything above
    (PACKAGE / "MANIFEST.json").write_text(build_manifest(), encoding="utf-8")
    print("regenerated ISSUE_BACKLOG.csv, BACKLOG_SUMMARY.md, DEPENDENCY_GRAPH.md, MANIFEST.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regenerate", action="store_true", help="rewrite derived artifacts")
    args = parser.parse_args()

    try:
        issues = load_issues()
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if args.regenerate:
        errors: list[str] = []
        check_deps(issues, errors)
        check_acyclic(issues, errors)
        check_order(issues, errors)
        if errors:
            print("refusing to regenerate; fix these first:", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            return 1
        regenerate(issues)
        return 0

    errors = []
    check_deps(issues, errors)
    check_acyclic(issues, errors)
    check_order(issues, errors)
    check_csv(issues, errors)
    check_manifest(errors)

    if errors:
        print(f"FAIL: {len(errors)} problem(s) in the execution package", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(
        f"OK: {len(issues)} issues, dependencies resolve, "
        "graph acyclic, order valid, manifest matches"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
