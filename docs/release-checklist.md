# Release Checklist

Use this checklist before every public release. It is written for maintainers
and agents that need a mechanical publish path.

## 1. Clean Generated Files

Remove local-only outputs before commit and push:

```powershell
Remove-Item -Recurse -Force .mypy_cache,.pytest_cache,.ruff_cache,dist -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Get-ChildItem -Recurse -Force -Directory -Filter __pycache__) -ErrorAction SilentlyContinue
Remove-Item -Force .coverage,coverage.xml -ErrorAction SilentlyContinue
```

These files are ignored by `.gitignore` and must not be part of a release
commit.

## 2. Run Quality Gates

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
uv run bandit -c pyproject.toml -r src
uv run pip-audit --skip-editable
uv run python -m dfcc.cli conformance run --suite primary
uv run python -m dfcc.cli conformance run --suite legacy
uv build
Remove-Item -Force dist/.gitignore -ErrorAction SilentlyContinue
uvx twine check dist/*.whl dist/*.tar.gz
```

## 3. Scan For Local Paths And Secrets

Search source, docs, tests, and release metadata:

```bash
rg -n --hidden --glob '!*.pyc' --glob '!.git/**' --glob '!.venv/**' --glob '!dist/**' \
  '(C:\\Users\\|/home/|/Users/|SECRET|TOKEN|API[_-]?KEY|PASSWORD|PRIVATE KEY|BEGIN RSA|BEGIN OPENSSH|pypi-|ghp_|github_pat_)' .
```

Expected result: no matches. If a generated coverage file appears, remove it
and rerun the scan.

## 4. Inspect Distribution Archives

After `uv build`, inspect the wheel and source distribution. They must not
contain caches, bytecode, coverage files, local paths, or secrets.

```powershell
@'
from pathlib import Path
import tarfile
import zipfile

for path in Path("dist").glob("*"):
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path) as archive:
            names = archive.getnames()
    else:
        raise SystemExit(f"unexpected file in dist: {path}")
    bad = [
        name for name in names
        if "__pycache__" in name
        or name.endswith(".pyc")
        or "coverage" in name
        or "C:" in name
        or "/home/" in name
        or "/Users/" in name
    ]
    if bad:
        raise SystemExit(f"{path} contains unexpected entries: {bad}")
    print(f"{path}: {len(names)} entries checked")
'@ | python -
```

## 5. Publish

The release workflow is `.github/workflows/workflow.yml`. It publishes to PyPI
through Trusted Publishing and does not use a long-lived PyPI token.

Required PyPI Trusted Publisher settings:

- Project: `future-claim-certifier`
- Publisher: GitHub
- Owner: `kadubon`
- Repository: `future-claim-certifier`
- Workflow: `workflow.yml`
- Environment: none / Any

Publish by pushing tag `v1.0.0` after `main` is green.

## 6. Verify After Publish

```bash
python -m venv .release-smoke
.release-smoke/Scripts/python -m pip install --upgrade pip
.release-smoke/Scripts/python -m pip install future-claim-certifier==1.0.0
.release-smoke/Scripts/dfcc conformance run --suite primary
```

Also verify:

- GitHub release exists and has artifacts attached.
- PyPI project page exists.
- `pip install future-claim-certifier==1.0.0` installs package `dfcc`.
- The project homepage points to the DOI.
