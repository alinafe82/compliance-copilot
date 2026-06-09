# Linting and Testing Standards

These standards define the checks expected before a pull request is marked ready. Run the sections for the
languages touched by the change.

## Required Gates

- Start from the default branch and keep the PR focused on one reviewable change.
- Run `git diff --check` and `git diff --cached --check` before committing.
- Run `repowave scan .` when `repowave.toml` is present.
- Run every applicable language command below. If a command needs credentials, a live service, or unavailable
  platform tooling, state that in the PR and run the closest local gate.
- Add or update tests for behavior changes. Documentation-only changes still need the diff and repository gates.

## Python

- Use `uv` with the checked-in lockfile.
- Run Ruff for linting and MyPy for typed service boundaries.
- Run Pytest for policy classification, retrieval, and copilot response behavior.
- Keep tests deterministic by using fixtures instead of live model, search, or policy service calls.

## Current Command Map

- Install: `uv sync --extra dev --locked`.
- Lint: `uv run make lint`.
- Type check: `uv run make type-check`.
- Tests: `uv run make test`.
- Coverage: `uv run make test-cov`.
- Full CI-equivalent gate: `uv run make ci`.
