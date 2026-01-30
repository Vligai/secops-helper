"""
Ollama Provider Implementation

Supports local LLM inference for air-gapped environments.
"""

import os
from typing import Dict, Any, Optional

import requests

from .base import AIProvider, AIResponse


class OllamaProvider(AIProvider):
    """Local Ollama implementation for air-gapped environments"""

    DEFAULT_MODEL = "llama3"
    DEFAULT_ENDPOINT = "http://localhost:11434"

    def __init__(
        self,
        endpoint: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        timeout: int = 120,  # Local models can be slower
    ):
        """
        Initialize Ollama provider.

        Args:
            endpoint: Ollama API endpoint (defaults to localhost:11434)
            model: Model to use (default: llama3)
            timeout: Request timeout in seconds
        """
        self._endpoint = endpoint or os.getenv("OLLAMA_ENDPOINT", self.DEFAULT_ENDPOINT)
        self._model = model
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def model(self) -> str:
        return self._model

    def is_available(self) -> bool:
        """Check if Ollama is running and reachable"""
        try:
            response = requests.get(f"{self._endpoint}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def analyze(
        self, prompt: str, context: Dict[str, Any], max_tokens: int = 2000, temperature: float = 0.3
    ) -> AIResponse:
        """
        Send analysis request to local Ollama instance.

        Args:
            prompt: The analysis prompt
            context: Additional context (includes system_prompt)
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature

        Returns:
            AIResponse with analysis results
        """
        from ..prompts.system import SECURITY_ANALYST_SYSTEM_PROMPT

        system_prompt = context.get("system_prompt", SECURITY_ANALYST_SYSTEM_PROMPT)

        # Combine system prompt and user prompt for Ollama
        full_prompt = f"{system_prompt}\n\n---\n\n{prompt}"

        response = requests.post(
            f"{self._endpoint}/api/generate",
            json={
                "model": self._model,
                "prompt": full_prompt,
                "stream": False,
                "options": {"num_predict": max_tokens, "temperature": temperature},
            },
            timeout=self._timeout,
        )

        if response.status_code != 200:
            raise RuntimeError(f"Ollama request failed: {response.status_code} - {response.text}")

        result = response.json()
        content = result.get("response", "")

        # Ollama doesn't provide token counts directly, estimate
        tokens_used = self.estimate_tokens(full_prompt + content)

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

    def list_models(self) -> list:
        """List available models on the Ollama instance"""
        try:
            response = requests.get(f"{self._endpoint}/api/tags", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            pass
        return []
