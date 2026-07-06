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
    version = project["version"]

    assert project["name"] == "future-claim-certifier"
    assert version in {"1.1.0.dev0", "1.1.0"}
    assert dfcc.__version__ == version
    assert openapi["info"]["version"] == version
    assert project["description"] == (
        "Replayable Python protocol engine for validating time-bound future claims "
        "from canonical artifacts."
    )
    assert project["urls"]["Homepage"] == "https://doi.org/10.5281/zenodo.21199529"
    assert project["urls"]["Source"] == "https://github.com/kadubon/future-claim-certifier"
    assert project["urls"]["Issues"] == ("https://github.com/kadubon/future-claim-certifier/issues")
    expected_status = (
        "Development Status :: 4 - Beta"
        if version.endswith(".dev0")
        else "Development Status :: 5 - Production/Stable"
    )
    assert expected_status in project["classifiers"]
    assert "rfc8785>=0.1.4" in project["dependencies"]
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
    assert ("PYPI_" + "TO" + "KEN") not in workflow_text

    publish_job = workflow["jobs"]["publish"]
    assert publish_job["permissions"] == {"id-token": "write"}
    assert "environment" not in publish_job
    publish_steps = publish_job["steps"]
    publish_uses = [step.get("uses", "") for step in publish_steps if isinstance(step, dict)]
    assert any("pypa/gh-action-pypi-publish@" in value for value in publish_uses)
    assert all(re.search(r"@[0-9a-f]{40}$", value) for value in publish_uses if "@" in value)

    build_steps = workflow["jobs"]["build"]["steps"]
    assert any(
        step.get("run") == "uvx twine check dist/*.whl dist/*.tar.gz" for step in build_steps
    )
    assert any(
        step.get("run") == "uv sync --locked --all-groups --python 3.11" for step in build_steps
    )
    assert any(step.get("run") == "uv run pytest" for step in build_steps)
    assert any(
        step.get("run") == "uv run python -m dfcc.cli conformance run --suite strict"
        for step in build_steps
    )
    assert any("SHA256SUMS.txt" in str(step.get("run", "")) for step in build_steps)
    build_uses = [step.get("uses", "") for step in build_steps if isinstance(step, dict)]
    assert any("actions/attest-build-provenance@" in value for value in build_uses)
    assert all(re.search(r"@[0-9a-f]{40}$", value) for value in build_uses if "@" in value)


def test_github_workflows_pin_actions_and_run_strict_checks() -> None:
    for path in (".github/workflows/ci.yml", ".github/workflows/workflow.yml"):
        workflow = yaml.safe_load(_read_text(path))
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if not isinstance(step, dict) or "uses" not in step:
                    continue
                assert re.search(r"@[0-9a-f]{40}$", step["uses"]), step["uses"]

    ci = yaml.safe_load(_read_text(".github/workflows/ci.yml"))
    runs = [
        step.get("run")
        for job in ci["jobs"].values()
        for step in job.get("steps", [])
        if isinstance(step, dict)
    ]
    assert "uv sync --locked --all-groups --python ${{ matrix.python-version }}" in runs
    assert "uv run python -m dfcc.cli conformance run --suite primary" in runs
    assert "uv run python -m dfcc.cli conformance run --suite legacy" in runs
    assert "uv run python -m dfcc.cli conformance run --suite strict" in runs
    assert (ROOT / ".github" / "CODEOWNERS").exists()
