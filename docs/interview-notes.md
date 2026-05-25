# Interview Notes

## 60-Second Explanation

This is a FastAPI service that summarizes PR or ticket risk for compliance review. It validates
input, masks obvious sensitive patterns, scores deterministic risk signals, and keeps optional
provider-generated summaries behind an interface.

## Decisions I Can Defend

- Compliance decisions stay human-owned.
- Redaction and scoring are deterministic because they need direct tests.
- Provider output is optional and should not be treated as the source of truth.

## Tradeoffs

Pattern-based masking is incomplete. It is useful as a defensive layer in a demo, but a real
service would need a stronger DLP strategy, authorization, retention rules, and audit logs.

## Fixes Made During Portfolio Hardening

- Removed role-targeted and inflated README language.
- Fixed pytest import configuration for fresh clones.
- Reworked an AWS-key masking test so the repo does not contain a key-shaped literal.
- Added GitHub Actions CI, architecture notes, ADR, and interview notes.

## Likely Questions

**Why not automate approval?**
Compliance approval needs accountability and context. This tool should reduce review toil, not
own the decision.

**How safe is the redaction?**
It catches obvious patterns only. I would treat it as a guardrail, not as complete DLP.

**What does this show for Engineering Productivity?**
It shows how internal review tooling can make manual work faster while preserving human
ownership of risky decisions.
