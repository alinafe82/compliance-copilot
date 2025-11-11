"""Security and PII masking utilities."""
import logging
import re

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a security-aware assistant. Do not output secrets or PII. "
    "Prefer actionable, auditable guidance with least-privilege principles. "
    "Focus on risk assessment, compliance implications, and concrete remediation steps."
)

# Comprehensive PII and secrets patterns
PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    # SSN patterns
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
    (re.compile(r"\b\d{9}\b"), "SSN_NO_DASH"),

    # Credit card patterns
    (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "CREDIT_CARD"),

    # API keys and tokens
    (re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9-_]{16,})['\"]?"), "API_KEY"),
    (re.compile(r"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['\"]?([A-Za-z0-9-_]{16,})['\"]?"), "SECRET_KEY"),
    (re.compile(r"(?i)(access[_-]?token|accesstoken)\s*[:=]\s*['\"]?([A-Za-z0-9-_.]{16,})['\"]?"), "ACCESS_TOKEN"),
    (re.compile(r"(?i)bearer\s+([A-Za-z0-9-_.]{16,})"), "BEARER_TOKEN"),

    # AWS keys
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS_ACCESS_KEY"),
    (re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), "AWS_SECRET_KEY"),

    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "EMAIL"),

    # Phone numbers
    (re.compile(r"\b(\+?1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "PHONE"),

    # IP addresses (private ones might be sensitive)
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "PRIVATE_IP"),
    (re.compile(r"\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b"), "PRIVATE_IP"),
    (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), "PRIVATE_IP"),

    # Generic password patterns
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?"), "PASSWORD"),
]


def mask_pii(text: str, keep_patterns: bool = False) -> str:
    """
    Mask PII and secrets in text.

    Args:
        text: Input text to sanitize
        keep_patterns: If True, show what was redacted (e.g., [REDACTED:API_KEY])

    Returns:
        Sanitized text with PII masked

    Raises:
        ValueError: If text is None or empty
    """
    if not text:
        raise ValueError("Input text cannot be None or empty")

    masked = text
    redactions: dict[str, int] = {}

    for pattern, label in PII_PATTERNS:
        matches = pattern.findall(masked)
        if matches:
            redactions[label] = redactions.get(label, 0) + len(matches)
            replacement = f"[REDACTED:{label}]" if keep_patterns else "[REDACTED]"
            masked = pattern.sub(replacement, masked)

    if redactions:
        logger.info(f"PII redaction summary: {redactions}")

    return masked


def validate_input_safety(text: str, max_length: int = 50000) -> tuple[bool, str]:
    """
    Validate input for safety concerns.

    Args:
        text: Input text to validate
        max_length: Maximum allowed length

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not text or not text.strip():
        return False, "Input text is empty"

    if len(text) > max_length:
        return False, f"Input exceeds maximum length of {max_length} characters"

    # Check for suspicious patterns
    suspicious_patterns = [
        (r"(?i)<script", "Potential XSS attempt detected"),
        (r"(?i)javascript:", "Potential JavaScript injection detected"),
        (r"(?i)(union\s+select|drop\s+table)", "Potential SQL injection detected"),
    ]

    for pattern, message in suspicious_patterns:
        if re.search(pattern, text):
            logger.warning(f"Security validation failed: {message}")
            return False, message

    return True, ""
