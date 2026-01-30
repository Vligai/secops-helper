"""
AI Prompt Templates for Security Analysis

Contains system prompts, analysis templates, and report generation prompts.
"""

from .system import SECURITY_ANALYST_SYSTEM_PROMPT
from .analysis import (
    ANALYSIS_PROMPT_TEMPLATE,
    build_analysis_prompt,
)
from .report import (
    REPORT_PROMPT_TEMPLATE,
    build_report_prompt,
)

__all__ = [
    "SECURITY_ANALYST_SYSTEM_PROMPT",
    "ANALYSIS_PROMPT_TEMPLATE",
    "build_analysis_prompt",
    "REPORT_PROMPT_TEMPLATE",
    "build_report_prompt",
]
