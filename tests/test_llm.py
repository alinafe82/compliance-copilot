"""Tests for LLM module."""
import pytest

from src.llm import LLMBackend, MockLLM, OpenAILLM, get_llm


class TestMockLLM:
    """Tests for MockLLM backend."""

    def test_mock_llm_is_backend(self):
        """Test that MockLLM implements LLMBackend."""
        llm = MockLLM()
        assert isinstance(llm, LLMBackend)

    def test_secret_scenario(self):
        """Test mock response for secret exposure."""
        llm = MockLLM()
        result = llm.complete("Found api key in code")
        assert "CRITICAL" in result or "secret" in result.lower()
        assert "rotate" in result.lower()

    def test_vulnerability_scenario(self):
        """Test mock response for vulnerability."""
        llm = MockLLM()
        result = llm.complete("SQL injection vulnerability found")
        assert "RISK" in result or "vulnerability" in result.lower()
        assert "security" in result.lower()

    def test_database_scenario(self):
        """Test mock response for database operations."""
        llm = MockLLM()
        result = llm.complete("Database migration with deletion")
        assert "RISK" in result or "database" in result.lower()

    def test_default_scenario(self):
        """Test mock response for normal case."""
        llm = MockLLM()
        result = llm.complete("Added new feature for user profile")
        assert "LOW RISK" in result or "low risk" in result.lower()

    def test_complete_with_parameters(self):
        """Test complete method accepts parameters."""
        llm = MockLLM()
        result = llm.complete("test", max_tokens=500, temperature=0.5)
        assert isinstance(result, str)
        assert len(result) > 0


class TestGetLLM:
    """Tests for LLM factory function."""

    def test_get_mock_llm(self):
        """Test getting mock LLM backend."""
        llm = get_llm("mock")
        assert isinstance(llm, MockLLM)

    def test_get_openai_llm_requires_api_key(self):
        """Test that OpenAI backend requires API key."""
        with pytest.raises(ValueError, match="requires api_key"):
            get_llm("openai")

    def test_get_openai_llm_with_api_key(self):
        """Test getting OpenAI backend with API key."""
        llm = get_llm("openai", api_key="test-key", model="gpt-4")
        assert isinstance(llm, OpenAILLM)
        assert llm.api_key == "test-key"
        assert llm.model == "gpt-4"

    def test_unknown_provider_raises_error(self):
        """Test that unknown provider raises ValueError."""
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            get_llm("unknown-provider")

    def test_default_provider_is_mock(self):
        """Test that default provider is mock."""
        llm = get_llm()
        assert isinstance(llm, MockLLM)

    def test_case_insensitive_provider(self):
        """Test that provider name is case insensitive."""
        llm1 = get_llm("MOCK")
        llm2 = get_llm("Mock")
        llm3 = get_llm("mock")
        assert all(isinstance(llm, MockLLM) for llm in [llm1, llm2, llm3])


class TestOpenAILLM:
    """Tests for OpenAI LLM backend (placeholder)."""

    def test_openai_complete_not_implemented(self):
        """Test that OpenAI complete raises NotImplementedError."""
        llm = OpenAILLM(api_key="test-key")
        with pytest.raises(NotImplementedError):
            llm.complete("test prompt")
