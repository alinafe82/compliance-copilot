"""Tests for scoring module."""
import pytest

from src.scoring import get_risk_level, score_risk


class TestScoreRisk:
    """Tests for risk scoring."""

    def test_no_risk_keywords(self):
        """Test scoring with no risk keywords."""
        summary = "Everything looks good and normal"
        score = score_risk(summary)
        assert 0.0 <= score <= 1.0
        assert score == 0.0

    def test_critical_keyword(self):
        """Test scoring with critical keyword."""
        summary = "Critical security issue detected"
        score = score_risk(summary)
        assert score >= 0.6

    def test_secret_keyword(self):
        """Test scoring with secret keyword."""
        summary = "Secret exposure detected"
        score = score_risk(summary)
        assert score >= 0.5

    def test_breach_keyword(self):
        """Test scoring with breach keyword."""
        summary = "Potential data breach risk"
        score = score_risk(summary)
        assert score >= 0.6

    def test_multiple_keywords(self):
        """Test scoring with multiple risk keywords."""
        summary = "Critical secret breach with exposed credentials"
        score = score_risk(summary)
        assert score >= 0.9

    def test_remediation_keywords(self):
        """Test scoring with remediation keywords."""
        summary = "Rotate keys and apply patch to fix the issue"
        score = score_risk(summary)
        assert 0.0 < score <= 0.5  # patch + rotate + fix = 0.2 + 0.2 + 0.1 = 0.5

    def test_compliance_keywords(self):
        """Test scoring with compliance keywords."""
        summary = "GDPR and HIPAA compliance concerns with PII handling"
        score = score_risk(summary)
        assert score >= 0.9

    def test_score_capped_at_one(self):
        """Test that score is capped at 1.0."""
        summary = "Critical breach vulnerability exploit secret exposed credential leak"
        score = score_risk(summary)
        assert score == 1.0

    def test_case_insensitive(self):
        """Test that scoring is case insensitive."""
        score1 = score_risk("CRITICAL")
        score2 = score_risk("critical")
        score3 = score_risk("CrItIcAl")
        assert score1 == score2 == score3

    def test_empty_summary_raises_error(self):
        """Test that empty summary raises ValueError."""
        with pytest.raises(ValueError, match="cannot be None or empty"):
            score_risk("")


class TestGetRiskLevel:
    """Tests for risk level categorization."""

    def test_low_risk(self):
        """Test low risk categorization."""
        assert get_risk_level(0.0) == "low"
        assert get_risk_level(0.1) == "low"
        assert get_risk_level(0.29) == "low"

    def test_medium_risk(self):
        """Test medium risk categorization."""
        assert get_risk_level(0.3) == "medium"
        assert get_risk_level(0.4) == "medium"
        assert get_risk_level(0.49) == "medium"

    def test_high_risk(self):
        """Test high risk categorization."""
        assert get_risk_level(0.5) == "high"
        assert get_risk_level(0.6) == "high"
        assert get_risk_level(0.69) == "high"

    def test_critical_risk(self):
        """Test critical risk categorization."""
        assert get_risk_level(0.7) == "critical"
        assert get_risk_level(0.8) == "critical"
        assert get_risk_level(1.0) == "critical"
