"""
AI Provider Implementations

Supports multiple AI providers:
- OpenAI (GPT-4)
- Anthropic (Claude)
- Ollama (Local LLM)
- Azure OpenAI
"""

from .base import AIProvider, AIResponse
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .ollama_provider import OllamaProvider
from .azure_provider import AzureOpenAIProvider

__all__ = [
    "AIProvider",
    "AIResponse",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "AzureOpenAIProvider",
]


def get_provider(provider_name: str, **kwargs) -> AIProvider:
    """
    Factory function to get AI provider by name.

    Args:
        provider_name: One of 'openai', 'anthropic', 'ollama', 'azure'
        **kwargs: Provider-specific configuration

    Returns:
        Configured AIProvider instance

    Raises:
        ValueError: If provider_name is not recognized
    """
    providers = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "ollama": OllamaProvider,
        "azure": AzureOpenAIProvider,
    }

    if provider_name not in providers:
        raise ValueError(
            f"Unknown provider: {provider_name}. " f"Available: {list(providers.keys())}"
        )

    return providers[provider_name](**kwargs)
