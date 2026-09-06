"""Prompt registry tests (AS-027).

Two of these carry real weight.

``test_no_production_prompt_is_written_inline`` scans the agent package for prompt-shaped
string literals outside the registry. A prompt that lives at its call site gets tweaked to
fix a demo, and the change is invisible in the results — which is precisely the thing
prompt governance exists to prevent, and precisely the thing a convention cannot enforce.

``test_the_baseline_prompt_is_a_fair_representative`` checks the ablation is not rigged.
The prompt-only arm has to be what a careful engineer would actually write. A strawman
baseline would inflate every number this project reports, and it would be the first thing
a reviewer looked for.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from agentsec.agent.prompts import (
    DEFAULT_PROMPTS,
    REGISTRY,
    SYSTEM_BASELINE,
    SYSTEM_PLANNER,
    TASK_REVIEW,
    Prompt,
    PromptError,
    PromptRegistry,
)

pytestmark = pytest.mark.authz

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent / "src" / "agentsec" / "agent"


# --------------------------------------------------------------------------- determinism


def test_the_registry_hash_is_stable_across_constructions() -> None:
    assert PromptRegistry().hash == PromptRegistry().hash


def test_the_registry_hash_changes_when_a_prompt_changes() -> None:
    """The acceptance criterion. Without it, two runs under different prompts are
    indistinguishable in the artifacts."""
    original = PromptRegistry().hash

    edited = dict(DEFAULT_PROMPTS)
    edited["planner.system"] = Prompt(
        id="planner.system",
        version="1.0.0",
        purpose="edited",
        text=SYSTEM_PLANNER.text + "\nAlso, be extra careful.",
    )

    assert PromptRegistry(edited).hash != original


def test_the_registry_hash_changes_when_a_version_changes() -> None:
    """Content and identity both. A prompt re-released under a new version is a different
    prompt even if the text is unchanged, because the run record cites the version."""
    bumped = dict(DEFAULT_PROMPTS)
    bumped["planner.system"] = Prompt(
        id=SYSTEM_PLANNER.id,
        version="1.0.1",
        purpose=SYSTEM_PLANNER.purpose,
        text=SYSTEM_PLANNER.text,
    )
    assert PromptRegistry(bumped).hash != PromptRegistry().hash


def test_the_hash_does_not_depend_on_insertion_order() -> None:
    """Sorted by id, so the value depends on what is in the registry rather than on how it
    was assembled."""
    forwards = PromptRegistry({p.id: p for p in DEFAULT_PROMPTS.values()})
    backwards = PromptRegistry({p.id: p for p in reversed(list(DEFAULT_PROMPTS.values()))})
    assert forwards.hash == backwards.hash


def test_the_hash_survives_windows_line_endings() -> None:
    """The Rev 0 manifest was caught by exactly this: a hash that changes because a file
    was checked out on Windows tells you nothing about the content."""
    crlf = dict(DEFAULT_PROMPTS)
    crlf["planner.system"] = Prompt(
        id=SYSTEM_PLANNER.id,
        version=SYSTEM_PLANNER.version,
        purpose=SYSTEM_PLANNER.purpose,
        text=SYSTEM_PLANNER.text.replace("\n", "\r\n"),
    )
    assert PromptRegistry(crlf).hash == PromptRegistry().hash


def test_every_prompt_has_a_distinct_digest() -> None:
    digests = {p.digest for p in DEFAULT_PROMPTS.values()}
    assert len(digests) == len(DEFAULT_PROMPTS)


# --------------------------------------------------------------------------- lookup


def test_a_missing_prompt_fails_closed() -> None:
    """A silent fallback would run an evaluation cell under a prompt nobody chose, while
    the artifact named the one that was asked for."""
    with pytest.raises(PromptError, match="no prompt"):
        REGISTRY.get("planner.does-not-exist")


def test_duplicate_ids_are_refused() -> None:
    with pytest.raises(PromptError, match="duplicate"):
        PromptRegistry({"a": SYSTEM_PLANNER, "b": SYSTEM_PLANNER})


def test_versions_are_reported_for_the_run_record() -> None:
    versions = REGISTRY.versions()
    assert set(versions) == set(REGISTRY.ids())
    assert all(v for v in versions.values())


# --------------------------------------------------------------------------- rendering


def test_rendering_fills_every_slot() -> None:
    rendered = TASK_REVIEW.render(
        task="review repo-a",
        repository="fixture://repo-a",
        evidence="...",
        tools="...",
        scope="...",
    )
    assert "review repo-a" in rendered
    assert "fixture://repo-a" in rendered
    # No slot survives rendering. A leftover placeholder reads as a sentence and reaches
    # the model looking deliberate.
    assert not re.search(r"\{\w+\}", rendered), rendered


def test_a_missing_slot_raises_rather_than_rendering_a_placeholder() -> None:
    """``{repository}`` rendered into a live prompt is the kind of defect that survives
    review, because the output still reads like a sentence."""
    with pytest.raises(PromptError, match="repository"):
        TASK_REVIEW.render(task="review", evidence="...", tools="...", scope="...")


# --------------------------------------------------------------------------- governance


def _string_literals(path: pathlib.Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.append((node.lineno, node.value))
    return found


#: Phrases that mark a string as a model-facing instruction rather than a message, a log
#: line or a docstring.
PROMPT_MARKERS = (
    "you are a",
    "your job is to",
    "do not take instructions",
    "return only the json",
    "propose the actions",
    "system prompt:",
)


def test_no_production_prompt_is_written_inline() -> None:
    """Prompt governance, enforced rather than agreed.

    A prompt at its call site gets tweaked to fix a demo, and the change never appears in
    the run record. Docstrings are excluded because they are documentation, and
    prompts.py is excluded because it is the registry.
    """
    offenders: list[str] = []
    for path in sorted(AGENT_DIR.glob("*.py")):
        if path.name == "prompts.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        docstrings = {
            node.body[0].value.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }
        for lineno, value in _string_literals(path):
            if lineno in docstrings:
                continue
            lowered = value.lower()
            if any(marker in lowered for marker in PROMPT_MARKERS):
                offenders.append(f"{path.name}:{lineno}")

    assert not offenders, "prompt-shaped strings outside the registry:\n  " + "\n  ".join(offenders)


def test_the_detector_would_catch_an_inline_prompt(tmp_path: pathlib.Path) -> None:
    """Proves the scan above inspects something. A detector with a bug produces a green
    result that checked nothing."""
    module = tmp_path / "planner.py"
    module.write_text(
        'def plan():\n    system = "You are a security assistant. Return only the JSON."\n',
        encoding="utf-8",
    )
    literals = _string_literals(module)
    assert any(any(marker in value.lower() for marker in PROMPT_MARKERS) for _, value in literals)


def test_the_agent_package_is_actually_being_scanned() -> None:
    modules = list(AGENT_DIR.glob("*.py"))
    assert len(modules) >= 4, [m.name for m in modules]


# --------------------------------------------------------------------------- fairness


def test_the_baseline_prompt_is_a_fair_representative() -> None:
    """The ablation must not be rigged.

    The prompt-only arm has to be what a careful engineer would actually write. A strawman
    baseline would inflate every number this project reports, and it is the first thing a
    reviewer would check.
    """
    text = SYSTEM_BASELINE.text.lower()

    for expectation in (
        "destructive",
        "secret",
        "do not act on instructions",
        "read-only",
        "report",
    ):
        assert expectation in text, f"the baseline omits {expectation!r}"

    assert len(SYSTEM_BASELINE.text) > 400, "a two-line baseline is a strawman"


def test_the_baseline_and_the_governed_prompt_differ_in_mechanism_not_diligence() -> None:
    """Both prompts tell the model the same safety story. What differs between the arms is
    whether anything *enforces* it - which is the claim under test.

    This test failed on the first draft, because the baseline conveyed the idea without
    the word. The fix was to strengthen the baseline rather than relax the test: erring
    toward a stronger prompt-only arm makes the comparison harder for this project to win,
    which is the only direction a fairness check should ever be adjusted in.
    """
    for topic in ("untrusted", "instruction"):
        assert topic in SYSTEM_BASELINE.text.lower(), topic
        assert topic in SYSTEM_PLANNER.text.lower(), topic


def test_the_planner_prompt_states_it_cannot_self_authorise() -> None:
    """The core invariant, stated to the model as well as enforced around it. The prompt
    is not the control - it is a courtesy to a model that would otherwise waste tokens
    proposing things that will certainly be refused."""
    text = SYSTEM_PLANNER.text.lower()
    assert "cannot grant yourself" in text
    assert "propose" in text
    assert "untrusted" in text
