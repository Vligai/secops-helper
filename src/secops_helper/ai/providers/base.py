"""
Abstract Base Class for AI Providers

Defines the interface that all AI providers must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum


class Verdict(Enum):
    """Threat verdict classification"""
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class Severity(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RecommendedAction:
    """A recommended security action"""
    priority: str  # "immediate", "short_term", "long_term"
    action: str
    details: str


@dataclass
class AIResponse:
    """Structured response from AI analysis"""
    content: str
    confidence: float
    tokens_used: int
    model: str
    cached: bool = False

    # Structured analysis results (parsed from content)
    verdict: Optional[Verdict] = None
    severity: Optional[Severity] = None
    key_findings: List[str] = field(default_factory=list)
    threat_context: Optional[str] = None
    threat_type: Optional[str] = None
    threat_actor: Optional[str] = None
    recommended_actions: List[RecommendedAction] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    siem_queries: Dict[str, str] = field(default_factory=dict)
    confidence_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary for JSON output"""
        return {
            "verdict": self.verdict.value if self.verdict else None,
            "confidence": self.confidence,
            "severity": self.severity.value if self.severity else None,
            "threat_type": self.threat_type,
            "threat_actor": self.threat_actor,
            "key_findings": self.key_findings,
            "threat_context": self.threat_context,
            "recommended_actions": [
                {
                    "priority": a.priority,
                    "action": a.action,
                    "details": a.details
                }
                for a in self.recommended_actions
            ],
            "mitre_attack": self.mitre_attack,
            "iocs": self.iocs,
            "siem_queries": self.siem_queries,
            "confidence_notes": self.confidence_notes,
            "metadata": {
                "model": self.model,
                "tokens_used": self.tokens_used,
                "cached": self.cached
            }
        }


class AIProvider(ABC):
    """Abstract base class for AI providers"""

    @abstractmethod
    def analyze(
        self,
        prompt: str,
        context: Dict[str, Any],
        max_tokens: int = 2000,
        temperature: float = 0.3
    ) -> AIResponse:
        """
        Send analysis request to AI provider.

        Args:
            prompt: The analysis prompt
            context: Additional context for the analysis
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature (lower = more consistent)

        Returns:
            AIResponse containing the analysis results
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if provider is configured and reachable.

        Returns:
            True if provider is ready to use
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the provider name"""
        pass

    @property
    @abstractmethod
    def model(self) -> str:
        """Return the model being used"""
        pass

    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for text.
        Default implementation uses rough approximation.
        Override for provider-specific counting.

        Args:
            text: Input text

        Returns:
            Estimated token count
        """
        # Rough approximation: ~4 characters per token
        return len(text) // 4
