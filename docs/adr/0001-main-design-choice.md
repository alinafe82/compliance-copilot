# ADR 0001: Keep Compliance Decisions Human-Owned

## Status

Accepted

## Context

Compliance review has accountability and context requirements that are not satisfied by a
summary alone.

## Decision

The service summarizes and scores risk signals, but it does not approve, reject, or enforce a
change.

## Consequences

This keeps the tool useful as reviewer assistance without overstating its authority. The
tradeoff is that a separate workflow is still needed for approvals and audit trails.
