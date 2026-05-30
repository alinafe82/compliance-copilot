"""LLM integration with pluggable backend support."""
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class LLMError(Exception):
    """Base exception for LLM-related errors."""
    pass


class LLMTimeoutError(LLMError):
    """Raised when LLM request times out."""
    pass


class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    @abstractmethod
    async def complete(
        self, prompt: str, max_tokens: int = 1000, temperature: float = 0.0
    ) -> str:
        """
        Generate completion from prompt.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0.0 = deterministic)

        Returns:
            Generated text

        Raises:
            LLMError: If generation fails
            LLMTimeoutError: If request times out
        """
        pass


class MockLLM(LLMBackend):
    """Mock LLM for testing and development."""

    async def complete(
        self, prompt: str, max_tokens: int = 1000, temperature: float = 0.0
    ) -> str:
        """Generate mock completion based on keywords."""
        logger.debug(f"MockLLM received prompt of length {len(prompt)}")

        prompt_lower = prompt.lower()

        # Simulate different risk scenarios
        if any(kw in prompt_lower for kw in ["secret", "api key", "credential", "password"]):
            return (
                "**CRITICAL RISK DETECTED**\n\n"
                "Potential secret exposure identified in the changes.\n\n"
                "**Top 3 Actions:**\n"
                "1. Immediately rotate any exposed credentials\n"
                "2. Add detect-secrets pre-commit hook to prevent future leaks\n"
                "3. Update .gitignore to exclude sensitive files\n\n"
                "**Compliance Impact:** High - May violate security policies"
            )

        if any(kw in prompt_lower for kw in ["breach", "vulnerability", "exploit", "injection"]):
            return (
                "**HIGH RISK - Security Vulnerability**\n\n"
                "Potential security vulnerability detected.\n\n"
                "**Top 3 Actions:**\n"
                "1. Conduct security review with AppSec team\n"
                "2. Run SAST/DAST security scans\n"
                "3. Apply security patches and validate fixes\n\n"
                "**Blast Radius:** Medium - May affect user data or system integrity"
            )

        if any(kw in prompt_lower for kw in ["database", "deletion", "drop table"]):
            return (
                "**MEDIUM RISK - Data Operations**\n\n"
                "Changes involve database operations that require careful review.\n\n"
                "**Top 3 Actions:**\n"
                "1. Ensure database migrations are reversible\n"
                "2. Test in staging environment first\n"
                "3. Plan for rollback procedures\n\n"
                "**Severity:** Medium"
            )

        # Default low-risk response
        return (
            "**LOW RISK**\n\n"
            "No critical security or compliance risks detected in the changes.\n\n"
            "**Recommended Actions:**\n"
            "1. Ensure code owner review is completed\n"
            "2. Run full test suite including integration tests\n"
            "3. Verify changes align with architectural guidelines\n\n"
            "**Assessment:** Changes appear standard and low-risk"
        )


class OpenAILLM(LLMBackend):
    """OpenAI Responses API backend."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4",
        timeout_seconds: float = 30.0,
        base_url: str = "https://api.openai.com/v1",
    ):
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.base_url = base_url.rstrip("/")
        logger.info(f"Initialized OpenAI backend with model {model}")

    async def complete(
        self, prompt: str, max_tokens: int = 1000, temperature: float = 0.0
    ) -> str:
        """Generate completion using the OpenAI Responses API."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.base_url}/responses",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "input": prompt,
                        "max_output_tokens": max_tokens,
                        "temperature": temperature,
                    },
                )
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError("OpenAI request timed out") from exc
        except httpx.HTTPStatusError as exc:
            message = _extract_openai_error(exc.response)
            raise LLMError(f"OpenAI API error {exc.response.status_code}: {message}") from exc
        except httpx.RequestError as exc:
            raise LLMError(f"OpenAI request failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise LLMError("OpenAI response did not include valid JSON") from exc
        return _extract_response_text(payload)


def _extract_openai_error(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text or "unknown error"
    error = payload.get("error")
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return error["message"]
    return "unknown error"


def _extract_response_text(payload: dict[str, Any]) -> str:
    direct_output = payload.get("output_text")
    if isinstance(direct_output, str) and direct_output.strip():
        return direct_output

    text_parts: list[str] = []
    output = payload.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    text_parts.append(block["text"])

    if text_parts:
        return "\n".join(text_parts).strip()

    raise LLMError("OpenAI response did not include output text")


def get_llm(
    provider: str = "mock",
    api_key: str | None = None,
    model: str | None = None,
    timeout_seconds: float | None = None,
) -> LLMBackend:
    """
    Factory function to get LLM backend instance.

    Args:
        provider: LLM provider name ("mock", "openai", etc.)
        api_key: API key for the provider (if required)
        model: Model name to use

    Returns:
        LLM backend instance

    Raises:
        ValueError: If provider is unknown or configuration is invalid
    """
    provider_lower = provider.lower()

    if provider_lower == "mock":
        logger.info("Using MockLLM backend")
        return MockLLM()

    elif provider_lower == "openai":
        if not api_key:
            raise ValueError("OpenAI provider requires api_key")
        return OpenAILLM(
            api_key=api_key,
            model=model or "gpt-4",
            timeout_seconds=timeout_seconds if timeout_seconds is not None else 30.0,
        )

    else:
        raise ValueError(f"Unknown LLM provider: {provider}")
