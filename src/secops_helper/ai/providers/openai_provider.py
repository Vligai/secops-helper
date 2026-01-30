"""
OpenAI Provider Implementation

Supports GPT-4 and GPT-3.5 models for security analysis.
"""

import os
from typing import Dict, Any, Optional

from .base import AIProvider, AIResponse


class OpenAIProvider(AIProvider):
    """OpenAI GPT implementation for security analysis"""

    DEFAULT_MODEL = "gpt-4-turbo"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        organization: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Initialize OpenAI provider.

        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model: Model to use (default: gpt-4-turbo)
            organization: OpenAI organization ID (optional)
            timeout: Request timeout in seconds
        """
        self._api_key = api_key or os.getenv("OPENAI_API_KEY")
        self._model = model
        self._organization = organization
        self._timeout = timeout
        self._client = None

    def _get_client(self):
        """Lazy initialization of OpenAI client"""
        if self._client is None:
            try:
                from openai import OpenAI

                self._client = OpenAI(
                    api_key=self._api_key, organization=self._organization, timeout=self._timeout
                )
            except ImportError:
                raise ImportError(
                    "OpenAI package not installed. " "Install with: pip install openai"
                )
        return self._client

    @property
    def name(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    def is_available(self) -> bool:
        """Check if OpenAI is configured and reachable"""
        if not self._api_key:
            return False
        try:
            client = self._get_client()
            # Quick API check
            client.models.list()
            return True
        except Exception:
            return False

    def analyze(
        self, prompt: str, context: Dict[str, Any], max_tokens: int = 2000, temperature: float = 0.3
    ) -> AIResponse:
        """
        Send analysis request to OpenAI.

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

        response = client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
        )

        content = response.choices[0].message.content
        tokens_used = response.usage.total_tokens if response.usage else 0

        return AIResponse(
            content=content,
            confidence=self._extract_confidence(content),
            tokens_used=tokens_used,
            model=self._model,
            cached=False,
        )

    def _extract_confidence(self, content: str) -> float:
        """
        Extract confidence percentage from response content.

        Args:
            content: AI response content

        Returns:
            Confidence as float (0.0 to 1.0)
        """
        import re

        # Look for patterns like "92% confidence" or "(92% confidence)"
        patterns = [
            r"(\d+(?:\.\d+)?)\s*%\s*confidence",
            r"confidence[:\s]+(\d+(?:\.\d+)?)\s*%",
            r"\((\d+(?:\.\d+)?)\s*%\)",
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return float(match.group(1)) / 100.0

        # Default to medium confidence if not specified
        return 0.5

    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count using tiktoken if available.

        Args:
            text: Input text

        Returns:
            Estimated token count
        """
        try:
            import tiktoken

            encoding = tiktoken.encoding_for_model(self._model)
            return len(encoding.encode(text))
        except ImportError:
            # Fall back to rough approximation
            return super().estimate_tokens(text)
