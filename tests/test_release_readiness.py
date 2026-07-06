from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

import dfcc

ROOT = Path(__file__).parents[1]


def _read_text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_release_metadata_matches_public_distribution() -> None:
    project = tomllib.loads(_read_text("pyproject.toml"))["project"]
    openapi = yaml.safe_load(_read_text("docs/openapi.yaml"))

    assert project["name"] == "future-claim-certifier"
    assert project["version"] == "1.0.0"
    assert dfcc.__version__ == "1.0.0"
    assert openapi["info"]["version"] == "1.0.0"
    assert project["description"] == (
        "Replayable Python protocol engine for validating time-bound future claims "
        "from canonical artifacts."
    )
    assert project["urls"]["Homepage"] == "https://doi.org/10.5281/zenodo.21199529"
    assert project["urls"]["Source"] == "https://github.com/kadubon/future-claim-certifier"
    assert project["urls"]["Issues"] == ("https://github.com/kadubon/future-claim-certifier/issues")
    assert "Development Status :: 5 - Production/Stable" in project["classifiers"]
    assert {
        "agent-safety",
        "authority-validation",
        "canonical-artifacts",
        "future-claims",
        "proof-checking",
        "runtime-verification",
    }.issubset(set(project["keywords"]))


def test_readme_and_docs_local_links_resolve() -> None:
    markdown_files = [
        ROOT / "README.md",
        *sorted((ROOT / "docs").glob("*.md")),
        ROOT / "SECURITY.md",
        ROOT / "CONTRIBUTING.md",
    ]
    for markdown_file in markdown_files:
        text = markdown_file.read_text(encoding="utf-8")
        for match in re.finditer(r"\[[^\]]+\]\(([^)]+)\)", text):
            target = match.group(1)
            if "://" in target or target.startswith("#") or target.startswith("mailto:"):
                continue
            local_target = target.split("#", 1)[0]
            if not local_target:
                continue
            assert (markdown_file.parent / local_target).resolve().exists(), (
                f"{markdown_file.relative_to(ROOT)} links to missing {target}"
            )


def test_publish_workflow_uses_pypi_trusted_publishing() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "workflow.yml"
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)

    assert workflow_path.name == "workflow.yml"
    assert '      - "v*.*.*"' in workflow_text
    assert "username:" not in workflow_text
    assert "password:" not in workflow_text
    assert "PYPI_TOKEN" not in workflow_text

    publish_job = workflow["jobs"]["publish"]
    assert publish_job["permissions"] == {"id-token": "write"}
    assert "environment" not in publish_job
    publish_steps = publish_job["steps"]
    assert any(
        step.get("uses") == "pypa/gh-action-pypi-publish@release/v1"
        for step in publish_steps
        if isinstance(step, dict)
    )

    build_steps = workflow["jobs"]["build"]["steps"]
    assert any(
        step.get("run") == "uvx twine check dist/*.whl dist/*.tar.gz" for step in build_steps
    )
    assert any(step.get("run") == "uv run pytest" for step in build_steps)
