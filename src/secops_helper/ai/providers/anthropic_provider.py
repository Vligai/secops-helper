"""
Anthropic Claude Provider Implementation

Supports Claude 3 models for security analysis.
"""

import os
from typing import Dict, Any, Optional

from .base import AIProvider, AIResponse


class AnthropicProvider(AIProvider):
    """Anthropic Claude implementation for security analysis"""

    DEFAULT_MODEL = "claude-3-opus-20240229"

    def __init__(
        self, api_key: Optional[str] = None, model: str = DEFAULT_MODEL, timeout: int = 30
    ):
        """
        Initialize Anthropic provider.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Model to use (default: claude-3-opus)
            timeout: Request timeout in seconds
        """
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self._model = model
        self._timeout = timeout
        self._client = None

    def _get_client(self):
        """Lazy initialization of Anthropic client"""
        if self._client is None:
            try:
                import anthropic

                self._client = anthropic.Anthropic(api_key=self._api_key, timeout=self._timeout)
            except ImportError:
                raise ImportError(
                    "Anthropic package not installed. " "Install with: pip install anthropic"
                )
        return self._client

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def model(self) -> str:
        return self._model

    def is_available(self) -> bool:
        """Check if Anthropic is configured"""
        return bool(self._api_key)

    def analyze(
        self, prompt: str, context: Dict[str, Any], max_tokens: int = 2000, temperature: float = 0.3
    ) -> AIResponse:
        """
        Send analysis request to Anthropic Claude.

        Args:
            prompt: The analysis prompt
            context: Additional context (includes system_prompt)
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature

        Returns:
            AIResponse with analysis results
        """
        from ..prompts.system import SECURITY_ANALYST_SYSTEM_PROMPT

        client = self._get_client()

        system_prompt = context.get("system_prompt", SECURITY_ANALYST_SYSTEM_PROMPT)

        response = client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
        )

        content = response.content[0].text
        tokens_used = response.usage.input_tokens + response.usage.output_tokens

        return AIResponse(
            content=content,
            confidence=self._extract_confidence(content),
            tokens_used=tokens_used,
            model=self._model,
            cached=False,
        )

    def _extract_confidence(self, content: str) -> float:
        """Extract confidence percentage from response content"""
        import re

        patterns = [
            r"(\d+(?:\.\d+)?)\s*%\s*confidence",
            r"confidence[:\s]+(\d+(?:\.\d+)?)\s*%",
            r"\((\d+(?:\.\d+)?)\s*%\)",
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return float(match.group(1)) / 100.0

        return 0.5
