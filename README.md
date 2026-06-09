# Compliance Copilot

A service that takes a pull request or ticket payload, masks secret-shaped values before any LLM call, scores the change against a fixed risk taxonomy, and returns a structured summary for a human reviewer.

The service summarises and scores. It never approves, rejects, comments, or mutates anything in the source system. That separation is the entire point.

> **Pattern-based redaction is not a DLP system.** The redactor catches things shaped like API keys, AWS credentials, JWTs, and other obvious secret formats. It does not catch business-secret strings, customer PII embedded in free text, or novel secret formats. Anywhere this code would touch real customer data, run a real DLP product alongside it.

## What this is and is not

This is:

- a redact-then-score-then-summarise pipeline for compliance review of code or ticket changes.
- structured output a reviewer can audit (risk level, category, signals, masked excerpt).
- a clear boundary between scoring (deterministic) and summarising (LLM, optional).

This is not:

- a complete DLP system.
- a policy-decision engine (it does not say "approve" or "reject").
- a ticketing system; it does not write back to GitHub or any tracker.

If the name "Copilot" makes you expect autocomplete or chat, that is not what this does. The name is up for revision; the engineering inside is the redact-score-summarise contract.

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

## Pipeline

The order of operations is the safety contract:

1. **Redact first.** `src.safety` masks anything matching the secret-shape patterns. The redacted payload is the only payload anything downstream sees.
2. **Score deterministically.** `src.scoring` walks the redacted payload, looks for risk signals (`*.env` touched, IAM policy changes, schema changes touching PII tables, etc.), and assigns a category and level.
3. **Summarise (optional).** `src.llm` produces a short natural-language summary of the redacted payload and the score. The LLM never sees an unredacted payload.

That order matters: redaction has to happen before any model boundary call, or the secret value is in someone else's prompt log.

## Service layout

- `src.safety` — secret-shape patterns and the redactor. This module gets the most test coverage.
- `src.scoring` — risk taxonomy and signal detection.
- `src.llm` — optional provider boundary. Mock backend is default.
- `src.app` — FastAPI endpoints.
- `src.config` — runtime settings.

Design notes: [docs/architecture.md](docs/architecture.md).

## What the tests prove

- secret-shape patterns redact API keys, AWS credentials, JWT-shaped tokens, and `*.pem`-style key headers.
- the redactor returns a redacted copy, not a mutation of the input.
- risk scoring assigns the right category for the documented signals.
- the service has no code path that approves or rejects a change; the response shape is strictly informational.
- 4xx and 5xx responses do not echo exception detail back to clients (see PR history for the relevant fix).

## Adapter work left before this would review real PRs

- A GitHub PR or webhook connector that turns a PR into the request payload.
- A ticket-system connector for the non-code half of the input.
- A persistence layer for reviewer feedback so the scoring rules can be tuned against actual approval rates.
- A real DLP product alongside, not behind, the pattern redactor.

## Operational notes

- [docs/runbook.md](docs/runbook.md) if present
- [docs/security-notes.md](docs/security-notes.md)
- [docs/production-readiness.md](docs/production-readiness.md)
- [docs/interview-notes.md](docs/interview-notes.md)
