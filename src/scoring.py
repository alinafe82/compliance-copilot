"""Risk scoring utilities."""
import logging

logger = logging.getLogger(__name__)

# Risk keywords with weights (keyword, weight, category)
RISK_KEYWORDS: list[tuple[str, float, str]] = [
    # Critical security issues
    ("critical", 0.6, "severity"),
    ("breach", 0.6, "security"),
    ("vulnerability", 0.5, "security"),
    ("exploit", 0.5, "security"),
    ("injection", 0.5, "security"),
    ("secret", 0.5, "security"),
    ("exposed", 0.5, "security"),
    ("leak", 0.5, "security"),

    # High impact operations
    ("unauthorized", 0.4, "access"),
    ("privilege", 0.3, "access"),
    ("authentication", 0.3, "access"),
    ("credential", 0.4, "security"),
    ("token", 0.3, "security"),

    # Compliance concerns
    ("compliance", 0.3, "compliance"),
    ("gdpr", 0.3, "compliance"),
    ("pii", 0.4, "compliance"),
    ("hipaa", 0.3, "compliance"),

    # Remediation indicators (lower weight, still important)
    ("rotate", 0.2, "remediation"),
    ("patch", 0.2, "remediation"),
    ("update", 0.1, "remediation"),
    ("fix", 0.1, "remediation"),

    # Infrastructure risks
    ("production", 0.3, "environment"),
    ("database", 0.2, "infrastructure"),
    ("deletion", 0.4, "data"),
    ("data loss", 0.5, "data"),
]


def score_risk(summary: str) -> float:
    """
    Calculate risk score from LLM summary.

    Uses weighted keyword matching with category-based analysis.
    Score is normalized to [0.0, 1.0] range.

    Args:
        summary: Risk summary text from LLM

    Returns:
        Risk score between 0.0 (low) and 1.0 (critical)

    Raises:
        ValueError: If summary is None or empty
    """
    if not summary:
        raise ValueError("Summary cannot be None or empty")

    summary_lower = summary.lower()
    score = 0.0
    category_scores: dict[str, float] = {}
    matched_keywords: list[str] = []

    for keyword, weight, category in RISK_KEYWORDS:
        if keyword in summary_lower:
            score += weight
            category_scores[category] = category_scores.get(category, 0.0) + weight
            matched_keywords.append(keyword)

    # Normalize score to [0, 1] range
    # Max theoretical score is sum of all weights, but we cap at 1.0
    normalized_score = min(score, 1.0)

    if matched_keywords:
        logger.info(
            f"Risk scoring: score={normalized_score:.2f}, "
            f"keywords={matched_keywords}, categories={category_scores}"
        )

    return normalized_score


def get_risk_level(score: float) -> str:
    """
    Convert numeric risk score to categorical risk level.

    Args:
        score: Risk score between 0.0 and 1.0

    Returns:
        Risk level string: "low", "medium", "high", or "critical"
    """
    if score >= 0.7:
        return "critical"
    elif score >= 0.5:
        return "high"
    elif score >= 0.3:
        return "medium"
    else:
        return "low"
