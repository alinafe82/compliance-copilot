# Compliance Copilot (AI PR & Ticket Risk Summarizer)

**uv-native + GitLab CI** demo for a Sr AI Agent Developer role.

## Dev Quickstart (uv)
```bash
uv venv
source .venv/bin/activate
uv pip install -e .[dev]
uv run uvicorn src.app:app --reload
# http://localhost:8000/docs
```

## CI/CD (GitLab)
- Lint/Type/Test via uv runner
- Security: gitleaks + bandit via `uvx`
- Build: Kaniko → GHCR on tags (set `GHCR_USERNAME`/`GHCR_TOKEN` variables)

Tag release:
```bash
git tag v0.1.0 && git push origin v0.1.0
```

---
© 2025. MIT.
