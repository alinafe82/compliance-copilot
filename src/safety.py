import re

SYSTEM_PROMPT = (
    "You are a security-aware assistant. Do not output secrets or PII. "
    "Prefer actionable, auditable guidance with least-privilege principles."
)

PII_PATTERNS = [
    re.compile(r"(\b\d{3}-\d{2}-\d{4}\b)"),  # SSN-like
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9-_]{16,}"),
]

def mask_pii(text: str) -> str:
    masked = text
    for pat in PII_PATTERNS:
        masked = pat.sub("[REDACTED]", masked)
    return masked
