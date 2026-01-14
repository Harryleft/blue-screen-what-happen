"""
BSOD analysis engine.

Core analyzer that combines parsing, detection, and AI analysis.
"""

from typing import List, Optional
from collections import Counter
from loguru import logger

from bsod_analyzer.core.parser import IMinidumpParser
from bsod_analyzer.core.bugcheck_kb import BugcheckKnowledgeBase
from bsod_analyzer.core.driver_detector import DriverDetector
from bsod_analyzer.database.models import (
    AnalysisResult,
    CrashInfo,
    DriverInfo,
    MinidumpInfo,
    StackTrace,
)


class BSODAnalyzer:
    """Blue Screen of Death analysis engine."""

    def __init__(
        self,
        parser: IMinidumpParser,
        kb: Optional[BugcheckKnowledgeBase] = None,
        driver_detector: Optional[DriverDetector] = None,
    ):
        """Initialize the analyzer.

        Args:
            parser: Minidump parser instance
            kb: Bugcheck knowledge base (optional, will create if None)
            driver_detector: Driver detector (optional, will create if None)
        """
        self.parser = parser
        self.kb = kb or BugcheckKnowledgeBase()
        self.driver_detector = driver_detector or DriverDetector()

    def analyze(self, dump_file: str, use_ai: bool = False) -> AnalysisResult:
        """Perform complete analysis of a dump file.

        Args:
            dump_file: Path to the dump file
            use_ai: Whether to use AI for enhanced analysis

        Returns:
            AnalysisResult containing all analysis data
        """
        logger.info(f"Starting analysis of: {dump_file}")

        # Step 1: Parse basic information
        logger.debug("Parsing minidump info...")
        minidump_info = self.parser.parse(dump_file)

        # Step 2: Extract crash information
        logger.debug("Extracting crash info...")
        crash_info = self.parser.extract_crash_info()

        # Step 3: Get loaded drivers
        logger.debug("Getting loaded drivers...")
        drivers = self.parser.get_loaded_drivers()

        # Step 4: Get stack traces
        logger.debug("Getting stack traces...")
        stack_traces = self.parser.get_stack_traces()

        # Step 5: Find suspected driver
        logger.debug("Finding suspected driver...")
        suspected_driver = self._find_suspected_driver(crash_info, drivers, stack_traces)

        # Step 6: Determine cause
        logger.debug("Determining cause...")
        suspected_cause = self._determine_cause(crash_info, suspected_driver, stack_traces)

        # Step 7: Generate recommendations
        logger.debug("Generating recommendations...")
        recommendations = self._generate_recommendations(crash_info, suspected_driver)

        # Step 8: Calculate confidence
        logger.debug("Calculating confidence...")
        confidence = self._calculate_confidence(crash_info, suspected_driver, stack_traces)

        # Update problematic flag on suspected driver
        if suspected_driver:
            suspected_driver.is_problematic = self.driver_detector.is_problematic(suspected_driver)

        result = AnalysisResult(
            dump_file=dump_file,
            minidump_info=minidump_info,
            crash_info=crash_info,
            loaded_drivers=drivers,
            stack_traces=stack_traces,
            suspected_cause=suspected_cause,
            suspected_driver=suspected_driver,
            recommendations=recommendations,
            confidence=confidence,
            ai_analysis=None,  # Will be filled by AI analyzer if enabled
        )

        logger.info(f"Analysis complete. Confidence: {confidence:.2%}")
        return result

    def _find_suspected_driver(
        self, crash_info: CrashInfo, drivers: List[DriverInfo], stack_traces: List[StackTrace]
    ) -> Optional[DriverInfo]:
        """Find the most likely problematic driver.

        Uses multiple strategies:
        1. Check stack top frames
        2. Check known problematic drivers
        3. Check crash address location
        """
        # Strategy 1: Check stack top frames
        for trace in stack_traces:
            if trace.frames:
                top_frame = trace.frames[0]
                driver = self._find_driver_by_address(drivers, top_frame.instruction_address)
                if driver:
                    # Exclude system drivers if possible
                    if not self.driver_detector.is_system_driver(driver.name):
                        logger.debug(f"Suspected driver from stack: {driver.name}")
                        return driver

        # Strategy 2: Check known problematic drivers
        for driver in drivers:
            if self.driver_detector.is_problematic(driver):
                logger.debug(f"Suspected driver from known bad list: {driver.name}")
                return driver

        # Strategy 3: Check crash address
        crash_driver = self._find_driver_by_address(drivers, crash_info.crash_address)
        if crash_driver:
            logger.debug(f"Suspected driver from crash address: {crash_driver.name}")
            return crash_driver

        logger.debug("No specific driver identified")
        return None

    def _find_driver_by_address(self, drivers: List[DriverInfo], address: int) -> Optional[DriverInfo]:
        """Find driver that contains the given address."""
        for driver in drivers:
            if driver.base_address <= address < driver.base_address + driver.size:
                return driver
        return None

    def _determine_cause(
        self, crash_info: CrashInfo, suspected_driver: Optional[DriverInfo], stack_traces: List[StackTrace]
    ) -> str:
        """Determine the root cause description."""
        # Get base description from knowledge base
        base_cause = self.kb.get_description(crash_info.bugcheck_code)

        # Add common causes
        common_causes = self.kb.get_common_causes(crash_info.bugcheck_code)
        if common_causes:
            base_cause += f" Common causes: {', '.join(common_causes[:3])}"

        # Add suspected driver info
        if suspected_driver:
            if self.driver_detector.is_problematic(suspected_driver):
                known_issue = self.driver_detector.get_known_issue(suspected_driver)
                return f"{base_cause} Known issue: {known_issue}"
            else:
                return f"{base_cause} Suspected driver: {suspected_driver.name}"

        return base_cause

    def _generate_recommendations(self, crash_info: CrashInfo, suspected_driver: Optional[DriverInfo]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        # Get general recommendations from knowledge base
        recommendations.extend(self.kb.get_recommendations(crash_info.bugcheck_code))

        # Add driver-specific recommendations
        if suspected_driver:
            if self.driver_detector.is_problematic(suspected_driver):
                rec = self.driver_detector.get_recommendation(suspected_driver)
                if rec:
                    recommendations.append(f"Driver-specific: {rec}")
            else:
                recommendations.append(f"Update '{suspected_driver.name}' to the latest version")

        # Analyze driver patterns
        if suspected_driver:
            driver_type = self.driver_detector.classify_driver(suspected_driver)
            if driver_type == "graphics":
                recommendations.append("Graphics drivers are often the cause - try a clean install of GPU drivers")
            elif driver_type == "network":
                recommendations.append("Network driver issues - update or temporarily disable network adapters")

        return list(set(recommendations))  # Remove duplicates

    def _calculate_confidence(
        self, crash_info: CrashInfo, suspected_driver: Optional[DriverInfo], stack_traces: List[StackTrace]
    ) -> float:
        """Calculate confidence score (0.0 - 1.0)."""
        confidence = 0.5  # Base confidence

        # Stack traces increase confidence
        if stack_traces and len(stack_traces[0].frames) > 0:
            confidence += 0.15

        # Found suspected driver
        if suspected_driver:
            confidence += 0.15

        # Known problematic driver - high confidence
        if suspected_driver and self.driver_detector.is_problematic(suspected_driver):
            confidence += 0.25

        # Common bugcheck codes
        common_codes = [0x0A, 0x3B, 0xD1, 0x50, 0x7E, 0x1E]
        if crash_info.bugcheck_code in common_codes:
            confidence += 0.1

        return min(confidence, 1.0)

    def analyze_multiple(self, dump_files: List[str]) -> List[AnalysisResult]:
        """Analyze multiple dump files.

        Args:
            dump_files: List of dump file paths

        Returns:
            List of analysis results
        """
        results = []

        for dump_file in dump_files:
            try:
                result = self.analyze(dump_file)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to analyze {dump_file}: {e}")

        return results

    def get_crash_patterns(self, results: List[AnalysisResult]) -> dict:
        """Analyze patterns across multiple crashes.

        Args:
            results: List of analysis results

        Returns:
            Dictionary containing pattern statistics
        """
        if not results:
            return {}

        # Count bugcheck codes
        bugcheck_counts = Counter(r.crash_info.bugcheck_code for r in results)

        # Count suspected drivers
        driver_counts = Counter(
            r.suspected_driver.name if r.suspected_driver else "Unknown" for r in results
        )

        # Average confidence
        avg_confidence = sum(r.confidence for r in results) / len(results)

        return {
            "total_crashes": len(results),
            "bugcheck_distribution": dict(bugcheck_counts.most_common(5)),
            "driver_distribution": dict(driver_counts.most_common(5)),
            "average_confidence": avg_confidence,
            "most_common_bugcheck": bugcheck_counts.most_common(1)[0] if bugcheck_counts else None,
        }
