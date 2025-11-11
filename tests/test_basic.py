from src.scoring import score_risk
from src.safety import mask_pii

def test_score_risk():
    assert 0.0 <= score_risk("All good") <= 1.0
    assert score_risk("Critical secret exposure, rotate keys") >= 0.6

def test_mask_pii():
    s = "SSN 123-45-6789 and api_key=ABCD1234EFGH5678"
    masked = mask_pii(s)
    assert "123-45-6789" not in masked
    assert "ABCD1234EFGH5678" not in masked
