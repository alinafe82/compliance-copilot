def score_risk(summary: str) -> float:
    summary_lower = summary.lower()
    score = 0.0
    for kw, w in [("critical", 0.6), ("secret", 0.5), ("breach", 0.5), ("rotate", 0.2)]:
        if kw in summary_lower:
            score += w
    return min(score, 1.0)
