"""Tests for LLM module."""
import httpx
import pytest

from src.llm import LLMBackend, LLMError, LLMTimeoutError, MockLLM, OpenAILLM, get_llm


class TestMockLLM:
    """Tests for MockLLM backend."""

    @pytest.mark.asyncio
    async def test_mock_llm_is_backend(self):
        """Test that MockLLM implements LLMBackend."""
        llm = MockLLM()
        assert isinstance(llm, LLMBackend)

    @pytest.mark.asyncio
    async def test_secret_scenario(self):
        """Test mock response for secret exposure."""
        llm = MockLLM()
        result = await llm.complete("Found api key in code")
        assert "CRITICAL" in result or "secret" in result.lower()
        assert "rotate" in result.lower()

    @pytest.mark.asyncio
    async def test_vulnerability_scenario(self):
        """Test mock response for vulnerability."""
        llm = MockLLM()
        result = await llm.complete("SQL injection vulnerability found")
        assert "RISK" in result or "vulnerability" in result.lower()
        assert "security" in result.lower()

    @pytest.mark.asyncio
    async def test_database_scenario(self):
        """Test mock response for database operations."""
        llm = MockLLM()
        result = await llm.complete("Database migration with deletion")
        assert "RISK" in result or "database" in result.lower()

    @pytest.mark.asyncio
    async def test_default_scenario(self):
        """Test mock response for normal case."""
        llm = MockLLM()
        result = await llm.complete("Added new feature for user profile")
        assert "LOW RISK" in result or "low risk" in result.lower()

    @pytest.mark.asyncio
    async def test_complete_with_parameters(self):
        """Test complete method accepts parameters."""
        llm = MockLLM()
        result = await llm.complete("test", max_tokens=500, temperature=0.5)
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
        api_key = "test-" + "key"
        llm = get_llm("openai", api_key=api_key, model="gpt-4", timeout_seconds=12)
        assert isinstance(llm, OpenAILLM)
        assert llm.api_key == api_key
        assert llm.model == "gpt-4"
        assert llm.timeout_seconds == 12

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
    """Tests for OpenAI LLM backend."""

    @pytest.mark.asyncio
    async def test_openai_complete_calls_responses_api(self, monkeypatch):
        """Test that OpenAI complete calls the Responses API."""
        captured: dict[str, object] = {}

        class FakeClient:
            def __init__(self, timeout):
                captured["timeout"] = timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def post(self, url, headers, json):
                captured.update(
                    {
                        "url": url,
                        "headers": headers,
                        "json": json,
                    }
                )
                return httpx.Response(
                    200,
                    json={
                        "output": [
                            {
                                "content": [
                                    {"type": "output_text", "text": "Reviewed risk summary."}
                                ]
                            }
                        ]
                    },
                    request=httpx.Request("POST", url),
                )

        monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
        llm = OpenAILLM(api_key="test-key", model="gpt-4o-mini", timeout_seconds=12)

        result = await llm.complete("test prompt", max_tokens=250, temperature=0.2)

        assert result == "Reviewed risk summary."
        assert captured["url"] == "https://api.openai.com/v1/responses"
        assert captured["headers"]["Authorization"] == "Bearer test-key"
        assert captured["json"] == {
            "model": "gpt-4o-mini",
            "input": "test prompt",
            "max_output_tokens": 250,
            "temperature": 0.2,
        }
        assert captured["timeout"] == 12

    @pytest.mark.asyncio
    async def test_openai_complete_handles_direct_output_text(self, monkeypatch):
        """Test direct output_text extraction."""

        class FakeClient:
            def __init__(self, timeout):
                self.timeout = timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def post(self, url, headers, json):
                return httpx.Response(
                    200,
                    json={"output_text": "Direct response."},
                    request=httpx.Request("POST", url),
                )

        monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
        llm = OpenAILLM(api_key="test-key")

        assert await llm.complete("test prompt") == "Direct response."

    @pytest.mark.asyncio
    async def test_openai_complete_maps_timeout(self, monkeypatch):
        """Test timeout mapping."""

        class FakeClient:
            def __init__(self, timeout):
                self.timeout = timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def post(self, url, headers, json):
                raise httpx.TimeoutException("timed out", request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
        llm = OpenAILLM(api_key="test-key")

        with pytest.raises(LLMTimeoutError, match="timed out"):
            await llm.complete("test prompt")

    @pytest.mark.asyncio
    async def test_openai_complete_maps_malformed_json(self, monkeypatch):
        """Test malformed upstream JSON is treated as an LLM failure."""

        class FakeClient:
            def __init__(self, timeout):
                self.timeout = timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def post(self, url, headers, json):
                return httpx.Response(
                    200,
                    content=b"not json",
                    request=httpx.Request("POST", url),
                )

        monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
        llm = OpenAILLM(api_key="test-key")

        with pytest.raises(LLMError, match="valid JSON"):
            await llm.complete("test prompt")
