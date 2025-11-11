"""Tests for safety module."""
import pytest

from src.safety import mask_pii, validate_input_safety


class TestMaskPII:
    """Tests for PII masking."""

    def test_mask_ssn(self):
        """Test SSN masking."""
        text = "My SSN is 123-45-6789"
        masked = mask_pii(text)
        assert "123-45-6789" not in masked
        assert "[REDACTED]" in masked

    def test_mask_api_key(self):
        """Test API key masking."""
        text = "api_key=ABCD1234EFGH5678IJKL"
        masked = mask_pii(text)
        assert "ABCD1234EFGH5678IJKL" not in masked
        assert "[REDACTED]" in masked

    def test_mask_email(self):
        """Test email masking."""
        text = "Contact me at user@example.com"
        masked = mask_pii(text)
        assert "user@example.com" not in masked
        assert "[REDACTED]" in masked

    def test_mask_aws_key(self):
        """Test AWS key masking."""
        text = "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"
        masked = mask_pii(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in masked
        assert "[REDACTED]" in masked

    def test_mask_credit_card(self):
        """Test credit card masking."""
        text = "Card: 4532-1234-5678-9010"
        masked = mask_pii(text)
        assert "4532-1234-5678-9010" not in masked
        assert "[REDACTED]" in masked

    def test_mask_phone_number(self):
        """Test phone number masking."""
        text = "Call me at (555) 123-4567"
        masked = mask_pii(text)
        assert "555" not in masked or "123" not in masked
        assert "[REDACTED]" in masked

    def test_mask_private_ip(self):
        """Test private IP masking."""
        text = "Server at 192.168.1.100"
        masked = mask_pii(text)
        assert "192.168.1.100" not in masked
        assert "[REDACTED]" in masked

    def test_mask_password(self):
        """Test password masking."""
        text = "password=MySecretPass123"
        masked = mask_pii(text)
        assert "MySecretPass123" not in masked
        assert "[REDACTED]" in masked

    def test_mask_with_keep_patterns(self):
        """Test masking with pattern labels."""
        text = "My email is test@example.com"
        masked = mask_pii(text, keep_patterns=True)
        assert "test@example.com" not in masked
        assert "[REDACTED:EMAIL]" in masked

    def test_empty_text_raises_error(self):
        """Test that empty text raises ValueError."""
        with pytest.raises(ValueError, match="cannot be None or empty"):
            mask_pii("")

    def test_no_pii_unchanged(self):
        """Test that text without PII is unchanged."""
        text = "This is a normal sentence without any sensitive data"
        masked = mask_pii(text)
        assert masked == text


class TestValidateInputSafety:
    """Tests for input validation."""

    def test_valid_input(self):
        """Test valid input passes."""
        is_valid, msg = validate_input_safety("This is valid text")
        assert is_valid is True
        assert msg == ""

    def test_empty_input(self):
        """Test empty input fails."""
        is_valid, msg = validate_input_safety("")
        assert is_valid is False
        assert "empty" in msg.lower()

    def test_whitespace_only_input(self):
        """Test whitespace-only input fails."""
        is_valid, msg = validate_input_safety("   \n\t  ")
        assert is_valid is False
        assert "empty" in msg.lower()

    def test_input_too_long(self):
        """Test input exceeding max length fails."""
        long_text = "a" * 100000
        is_valid, msg = validate_input_safety(long_text, max_length=50000)
        assert is_valid is False
        assert "exceeds maximum length" in msg

    def test_xss_detection(self):
        """Test XSS attempt detection."""
        text = "Hello <script>alert('xss')</script>"
        is_valid, msg = validate_input_safety(text)
        assert is_valid is False
        assert "XSS" in msg

    def test_javascript_injection_detection(self):
        """Test JavaScript injection detection."""
        text = "Click here: javascript:alert('hack')"
        is_valid, msg = validate_input_safety(text)
        assert is_valid is False
        assert "JavaScript injection" in msg

    def test_sql_injection_detection(self):
        """Test SQL injection detection."""
        text = "'; DROP TABLE users; --"
        is_valid, msg = validate_input_safety(text)
        assert is_valid is False
        assert "SQL injection" in msg
