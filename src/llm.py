"""LLM integration with pluggable backend support."""
import logging
from abc import ABC, abstractmethod

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
    def complete(self, prompt: str, max_tokens: int = 1000, temperature: float = 0.0) -> str:
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

    def complete(self, prompt: str, max_tokens: int = 1000, temperature: float = 0.0) -> str:
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
    """OpenAI LLM backend (placeholder for future implementation)."""

    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.api_key = api_key
        self.model = model
        logger.info(f"Initialized OpenAI backend with model {model}")

    def complete(self, prompt: str, max_tokens: int = 1000, temperature: float = 0.0) -> str:
        """Generate completion using OpenAI API."""
        # TODO: Implement OpenAI API integration
        # import openai
        # response = openai.ChatCompletion.create(...)
        raise NotImplementedError("OpenAI integration not yet implemented")


def get_llm(
    provider: str = "mock",
    api_key: str | None = None,
    model: str | None = None
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
        return OpenAILLM(api_key=api_key, model=model or "gpt-4")

    else:
        raise ValueError(f"Unknown LLM provider: {provider}")

