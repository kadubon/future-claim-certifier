# Contributing

Use `uv` for local development. Run the same checks locally before opening a
pull request:

```bash
uv sync --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
uv run bandit -c pyproject.toml -r src
uv run pip-audit --skip-editable
uv run python -m dfcc.cli conformance run --suite primary
uv run python -m dfcc.cli conformance run --suite legacy
```

Design constraints:

- Preserve the distinction between represented kernel verdicts and operational
  authority.
- Prefer typed records with reason references over bare enums.
- Missing or conflicting evidence must remain `unknown`, `conflict`, or blocked.
- Keep backend/proof generation separate from checker logic.
- Do not add network retrieval as a default behavior.

For public release work, follow [docs/release-checklist.md](docs/release-checklist.md).
