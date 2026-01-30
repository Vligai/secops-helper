"""
Azure OpenAI Provider Implementation

Supports Azure-hosted OpenAI models for enterprise environments.
"""

import os
from typing import Dict, Any, Optional

from .base import AIProvider, AIResponse


class AzureOpenAIProvider(AIProvider):
    """Azure OpenAI implementation for enterprise environments"""

    DEFAULT_API_VERSION = "2024-02-01"

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        deployment_name: Optional[str] = None,
        api_version: str = DEFAULT_API_VERSION,
        timeout: int = 30
    ):
        """
        Initialize Azure OpenAI provider.

        Args:
            api_key: Azure OpenAI API key (defaults to AZURE_OPENAI_API_KEY env var)
            endpoint: Azure endpoint URL (defaults to AZURE_OPENAI_ENDPOINT env var)
            deployment_name: Model deployment name (defaults to AZURE_OPENAI_DEPLOYMENT env var)
            api_version: Azure API version
            timeout: Request timeout in seconds
        """
        self._api_key = api_key or os.getenv('AZURE_OPENAI_API_KEY')
        self._endpoint = endpoint or os.getenv('AZURE_OPENAI_ENDPOINT')
        self._deployment_name = deployment_name or os.getenv(
            'AZURE_OPENAI_DEPLOYMENT',
            'gpt-4'
        )
        self._api_version = api_version
        self._timeout = timeout
        self._client = None

    def _get_client(self):
        """Lazy initialization of Azure OpenAI client"""
        if self._client is None:
            try:
                from openai import AzureOpenAI
                self._client = AzureOpenAI(
                    api_key=self._api_key,
                    api_version=self._api_version,
                    azure_endpoint=self._endpoint,
                    timeout=self._timeout
                )
            except ImportError:
                raise ImportError(
                    "OpenAI package not installed. "
                    "Install with: pip install openai"
                )
        return self._client

    @property
    def name(self) -> str:
        return "azure"

    @property
    def model(self) -> str:
        return self._deployment_name

    def is_available(self) -> bool:
        """Check if Azure OpenAI is configured"""
        return bool(self._api_key and self._endpoint and self._deployment_name)

    def analyze(
        self,
        prompt: str,
        context: Dict[str, Any],
        max_tokens: int = 2000,
        temperature: float = 0.3
    ) -> AIResponse:
        """
        Send analysis request to Azure OpenAI.

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

        system_prompt = context.get('system_prompt', SECURITY_ANALYST_SYSTEM_PROMPT)

        response = client.chat.completions.create(
            model=self._deployment_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=temperature
        )

        content = response.choices[0].message.content
        tokens_used = response.usage.total_tokens if response.usage else 0

        return AIResponse(
            content=content,
            confidence=self._extract_confidence(content),
            tokens_used=tokens_used,
            model=self._deployment_name,
            cached=False
        )

    def _extract_confidence(self, content: str) -> float:
        """Extract confidence percentage from response content"""
        import re

        patterns = [
            r'(\d+(?:\.\d+)?)\s*%\s*confidence',
            r'confidence[:\s]+(\d+(?:\.\d+)?)\s*%',
            r'\((\d+(?:\.\d+)?)\s*%\)',
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return float(match.group(1)) / 100.0

        return 0.5
