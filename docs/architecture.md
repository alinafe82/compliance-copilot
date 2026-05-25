# Architecture

## Problem

PRs and tickets can contain change details that matter for compliance review, but reviewers
often have to scan long, unstructured text. The goal is to summarize likely risk areas while
redacting obvious sensitive values and keeping final judgment with a human reviewer.

## Intended User

The intended user is an internal platform, security, or compliance engineering team that needs
review assistance for changes and tickets.

## Components

- FastAPI app: request validation and HTTP interface.
- Safety utilities: pattern-based masking and input validation.
- Scoring: deterministic risk signals and severity levels.
- LLM provider interface: optional summary generation behind a replaceable boundary.
- Config: environment-driven runtime settings.

## Data Flow

A caller submits change context. The service validates input, masks obvious sensitive values,
scores deterministic risk signals, and returns a summary suitable for human review.

## Design Choices

I kept redaction and scoring deterministic because those paths need to be testable. Provider
text generation is optional and should not be the source of truth for compliance decisions.

I avoided claims that the service is ready for regulated deployment. A real deployment would require
identity, authorization, audit logs, data retention policy, and deeper DLP controls.

## What Is Not Built

This is not a compliance decision engine, DLP product, or approval workflow. It does not ingest
private PRs or tickets from external systems.

## Extension Points

- Add GitHub and ticket-system adapters.
- Add structured risk categories and reviewer assignment.
- Persist reviewer feedback for scoring calibration.
- Add audit logging and authorization.

## Operational Considerations

A production service should avoid logging secrets, enforce access controls, store review
events with retention limits, and make human approval explicit.

## Testing Strategy

Tests cover masking, scoring, provider behavior, and API paths. A production adapter would need
contract tests and fixture-based redaction tests.
