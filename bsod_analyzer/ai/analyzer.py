"""
AI analysis engine.

Integrates with ZhipuAI to provide intelligent crash analysis.
"""

from typing import Optional, List, Dict, Any
from loguru import logger

from bsod_analyzer.ai.providers import IAIProvider, AIProviderFactory
from bsod_analyzer.ai.prompts import PromptTemplates
from bsod_analyzer.database.models import (
    CrashInfo,
    DriverInfo,
    StackTrace,
    MinidumpInfo,
)


class AIAnalyzer:
    """AI-powered crash analysis engine."""

    def __init__(self, provider: Optional[IAIProvider] = None, prompts: Optional[PromptTemplates] = None):
        """Initialize the AI analyzer.

        Args:
            provider: AI provider instance (optional)
            prompts: Prompt templates instance (optional)
        """
        self.provider = provider
        self.prompts = prompts or PromptTemplates()
        self._enabled = provider is not None and provider.is_available()

    @property
    def enabled(self) -> bool:
        """Check if AI analysis is enabled."""
        return self._enabled

    def analyze(
        self,
        crash_info: CrashInfo,
        drivers: List[DriverInfo],
        stack_traces: List[StackTrace],
        minidump_info: MinidumpInfo,
        suspected_driver: Optional[DriverInfo] = None,
    ) -> str:
        """Perform AI analysis of a crash.

        Args:
            crash_info: Crash information
            drivers: List of loaded drivers
            stack_traces: Stack traces
            minidump_info: Minidump information
            suspected_driver: Suspected problematic driver

        Returns:
            AI analysis text
        """
        if not self.enabled:
            return "AI analysis is not available. Please configure ZHIPU_API_KEY."

        # Build context
        context = self._build_context(
            crash_info, drivers, stack_traces, minidump_info, suspected_driver
        )

        # Generate prompt
        prompt = self.prompts.generate_analysis_prompt(context)

        # Call AI
        try:
            logger.info("Requesting AI analysis...")
            result = self.provider.analyze(prompt)
            logger.info("AI analysis complete")
            return result
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return f"AI analysis failed: {e}"

    def analyze_history(self, crashes: List[Dict[str, Any]]) -> str:
        """Analyze crash patterns from history.

        Args:
            crashes: List of crash records

        Returns:
            AI pattern analysis text
        """
        if not self.enabled:
            return "AI analysis is not available."

        if len(crashes) < 2:
            return "Need at least 2 crashes for pattern analysis."

        # Generate prompt
        prompt = self.prompts.generate_history_analysis_prompt(crashes)

        # Call AI
        try:
            logger.info(f"Requesting AI pattern analysis for {len(crashes)} crashes...")
            result = self.provider.analyze(prompt)
            logger.info("AI pattern analysis complete")
            return result
        except Exception as e:
            logger.error(f"AI pattern analysis failed: {e}")
            return f"AI pattern analysis failed: {e}"

    def analyze_driver(self, driver_name: str, crash_context: Dict[str, Any]) -> str:
        """Analyze a specific driver.

        Args:
            driver_name: Name of the driver
            crash_context: Crash context information

        Returns:
            AI driver analysis text
        """
        if not self.enabled:
            return "AI analysis is not available."

        # Generate prompt
        prompt = self.prompts.generate_driver_analysis_prompt(driver_name, crash_context)

        # Call AI
        try:
            logger.info(f"Requesting AI driver analysis for: {driver_name}")
            result = self.provider.analyze(prompt)
            logger.info("AI driver analysis complete")
            return result
        except Exception as e:
            logger.error(f"AI driver analysis failed: {e}")
            return f"AI driver analysis failed: {e}"

    def _build_context(
        self,
        crash_info: CrashInfo,
        drivers: List[DriverInfo],
        stack_traces: List[StackTrace],
        minidump_info: MinidumpInfo,
        suspected_driver: Optional[DriverInfo],
    ) -> Dict[str, Any]:
        """Build analysis context from crash data.

        Args:
            crash_info: Crash information
            drivers: List of loaded drivers
            stack_traces: Stack traces
            minidump_info: Minidump information
            suspected_driver: Suspected problematic driver

        Returns:
            Context dictionary for prompt generation
        """
        # Format drivers list
        driver_list = self.prompts.format_driver_list(drivers, max_drivers=20)

        # Format stack traces
        stack_text = self.prompts.format_stack_traces(stack_traces, max_threads=3, max_frames=10)

        return {
            "bugcheck_code": f"0x{crash_info.bugcheck_code:02X}",
            "bugcheck_name": crash_info.bugcheck_name,
            "bugcheck_description": crash_info.bugcheck_description,
            "crash_address": f"0x{crash_info.crash_address:X}",
            "crash_parameters": ", ".join(f"0x{p:X}" for p in crash_info.parameters),
            "suspected_driver": suspected_driver.name if suspected_driver else "未知",
            "computer_name": minidump_info.computer_name,
            "os_version": minidump_info.os_version,
            "cpu_architecture": minidump_info.cpu_architecture,
            "physical_memory": minidump_info.physical_memory // (1024 * 1024),
            "number_of_processors": minidump_info.number_of_processors,
            "driver_count": len(drivers),
            "driver_list": driver_list,
            "stack_traces": stack_text,
        }

    @classmethod
    def from_config(cls, config) -> "AIAnalyzer":
        """Create AIAnalyzer from configuration.

        Args:
            config: Config object from utils.config

        Returns:
            AIAnalyzer instance
        """
        provider = AIProviderFactory.create_from_config(config)
        return cls(provider=provider)
