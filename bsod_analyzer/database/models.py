"""
Data models for BSOD Analyzer.

Defines all data structures used throughout the application.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class BugCheckCode(Enum):
    """Windows Bugcheck code enumeration."""

    IRQL_NOT_LESS_OR_EQUAL = 0x0A
    SYSTEM_SERVICE_EXCEPTION = 0x3B
    KERNEL_MODE_HEAP_CORRUPTION = 0x13A
    DRIVER_IRQL_NOT_LESS_OR_EQUAL = 0xD1
    PAGE_FAULT_IN_NONPAGED_AREA = 0x50
    KERNEL_DATA_INPAGE_ERROR = 0x7A
    UNEXPECTED_KERNEL_MODE_TRAP = 0x7F
    KMODE_EXCEPTION_NOT_HANDLED = 0x1E
    WHEA_UNCORRECTABLE_ERROR = 0x124
    DPC_WATCHDOG_VIOLATION = 0x133
    CRITICAL_PROCESS_DIED = 0xEF
    SYSTEM_THREAD_EXCEPTION_NOT_HANDLED = 0x7E
    BAD_POOL_HEADER = 0x19
    MEMORY_MANAGEMENT = 0x1A
    DRIVER_VERIFIER_DETECTED_VIOLATION = 0xC4
    ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY = 0xFC


@dataclass
class MinidumpInfo:
    """Basic information about a minidump file."""

    file_path: str
    file_size: int
    timestamp: datetime
    computer_name: str
    os_version: str
    cpu_architecture: str
    number_of_processors: int
    physical_memory: int


@dataclass
class CrashInfo:
    """Crash information extracted from dump."""

    bugcheck_code: int
    bugcheck_name: str
    bugcheck_description: str
    crash_address: int
    crash_thread_id: int
    process_name: Optional[str] = None
    exception_record: Optional[Dict[str, Any]] = None
    parameters: List[int] = field(default_factory=list)


@dataclass
class DriverInfo:
    """Driver/module information."""

    name: str
    base_address: int
    size: int
    timestamp: datetime
    version: Optional[str] = None
    company: Optional[str] = None
    is_signed: bool = False
    is_problematic: bool = False


@dataclass
class StackFrame:
    """Single stack frame."""

    instruction_address: int
    module_name: str
    function_name: Optional[str] = None
    offset: int = 0
    source_file: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class StackTrace:
    """Stack trace information."""

    thread_id: int
    frames: List[StackFrame]


@dataclass
class AnalysisResult:
    """Complete analysis result."""

    dump_file: str
    minidump_info: MinidumpInfo
    crash_info: CrashInfo
    loaded_drivers: List[DriverInfo]
    stack_traces: List[StackTrace]
    suspected_cause: Optional[str] = None
    suspected_driver: Optional[DriverInfo] = None
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 - 1.0
    ai_analysis: Optional[str] = None
    analyzed_at: datetime = field(default_factory=datetime.now)


@dataclass
class CrashHistory:
    """Crash history record for database."""

    id: Optional[int] = None
    dump_file_path: str = ""
    crash_time: datetime = field(default_factory=datetime.now)
    bugcheck_code: int = 0
    bugcheck_name: str = ""
    suspected_driver: Optional[str] = None
    confidence: float = 0.0
    analysis_result: Optional[str] = None  # JSON stored
    created_at: datetime = field(default_factory=datetime.now)
