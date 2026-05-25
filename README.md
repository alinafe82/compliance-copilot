# Compliance Copilot

PR and ticket risk summarizer for compliance review workflows.

The service accepts change context, masks obvious sensitive values, scores risk signals, and
returns a concise review summary. It is meant to demonstrate API structure and safety checks
for internal review tooling, not to replace a compliance program.

## Why It Exists

Security and compliance review often starts with unstructured PRs and tickets. A lightweight
summarizer can help reviewers find risky areas faster if it is honest about confidence,
redacts obvious secrets, and keeps humans in the approval path.

## Quickstart

```bash
uv venv
source .venv/bin/activate
uv pip install -e .[dev]
uv run uvicorn src.app:app --reload
# http://localhost:8000/docs
```

Run tests and linting:

```bash
uv run --extra dev pytest
uv run --extra dev ruff check .
```

## Architecture Overview

- `src.app` exposes FastAPI endpoints.
- `src.safety` masks obvious PII and secret-like values.
- `src.scoring` assigns risk levels from review signals.
- `src.llm` isolates optional provider-backed summary generation.
- `src.config` centralizes runtime settings.

See [docs/architecture.md](docs/architecture.md) for design details.

## Limitations

- Redaction is pattern-based and should not be treated as a complete DLP system.
- Risk scoring is heuristic.
- The service summarizes risk; it does not approve or reject changes.

## Future Improvements

- Add source connectors for GitHub PRs and ticket systems.
- Add structured risk categories with owner routing.
- Add audit logging and reviewer feedback.

## Interview Notes

See [docs/interview-notes.md](docs/interview-notes.md).
