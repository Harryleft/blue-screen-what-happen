"""
Minidump file parser.

Uses the skelsec/minidump library to parse Windows crash dump files.
Also supports PAGEDU64 format (Windows Complete Memory Dump) via PageDumpParser.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from loguru import logger

from bsod_analyzer.database.models import (
    MinidumpInfo,
    CrashInfo,
    DriverInfo,
    StackTrace,
    StackFrame,
)


class IMinidumpParser(ABC):
    """Minidump parser interface."""

    @abstractmethod
    def parse(self, file_path: str) -> MinidumpInfo:
        """Parse minidump file basic information."""
        pass

    @abstractmethod
    def extract_crash_info(self) -> CrashInfo:
        """Extract crash information."""
        pass

    @abstractmethod
    def get_loaded_drivers(self) -> List[DriverInfo]:
        """Get list of loaded drivers."""
        pass

    @abstractmethod
    def get_stack_traces(self) -> List[StackTrace]:
        """Get stack traces."""
        pass

    @abstractmethod
    def get_exception_record(self) -> Optional[dict]:
        """Get exception record."""
        pass


class MinidumpParser(IMinidumpParser):
    """Minidump parser using skelsec/minidump library."""

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self._minidump = None
        self._dump_type = None
        self._validate_file()
        self._load_minidump()

    def _validate_file(self):
        """Validate file exists and has correct signature."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"Dump file not found: {self.file_path}")

        if self.file_path.stat().st_size == 0:
            raise ValueError(f"Empty dump file: {self.file_path}")

        # Validate file signature - support both MDMP and kernel dump formats
        with open(self.file_path, "rb") as f:
            signature = f.read(8)
            # Standard minidump
            if signature[:4] == b"MDMP":
                self._dump_type = "minidump"
            # Kernel dump formats
            elif signature[:8] == b"PAGEDU64":
                self._dump_type = "kernel_x64"
            elif signature[:8] == b"PAGEDU48":
                self._dump_type = "kernel_x86"
            else:
                raise ValueError(f"Invalid dump file signature: {signature[:8].hex()}")

    def _load_minidump(self):
        """Load minidump file."""
        try:
            from minidump.minidumpfile import MinidumpFile

            self._minidump = MinidumpFile.parse(str(self.file_path))
            logger.debug(f"Successfully loaded dump: {self.file_path} (type: {self._dump_type})")
        except ImportError as e:
            raise RuntimeError(
                f"minidump library not found. Install with: pip install minidump. Error: {e}"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to parse dump file: {e}")

    def parse(self, file_path: str) -> MinidumpInfo:
        """Parse and return minidump basic information."""
        sys_info = self._minidump.sysinfo

        # Get architecture name
        arch_map = {
            0: "INTEL",
            9: "AMD64",
            6: "IA64",
            5: "ARM",
            12: "ARM64",
            0xFFFF: "UNKNOWN",
        }
        arch = arch_map.get(sys_info.processor_architecture, f"UNKNOWN({sys_info.processor_architecture})")

        # Get computer name
        computer_name = ""
        if hasattr(sys_info, "computer_name"):
            computer_name = sys_info.computer_name.decode("utf-8", errors="ignore")

        # Get OS version
        os_version = f"{sys_info.major_version}.{sys_info.minor_version}.{sys_info.build_number}"

        # Get timestamp
        timestamp = datetime.fromtimestamp(self._minidump.header.time_date_stamp)

        return MinidumpInfo(
            file_path=str(self.file_path),
            file_size=self.file_path.stat().st_size,
            timestamp=timestamp,
            computer_name=computer_name,
            os_version=os_version,
            cpu_architecture=arch,
            number_of_processors=sys_info.number_of_processors,
            physical_memory=getattr(sys_info, "physical_memory", 0),
        )

    def extract_crash_info(self) -> CrashInfo:
        """Extract crash information from minidump."""
        # Try to get exception record
        exception = self.get_exception_record()

        if exception:
            bugcheck_code = exception.get("exception_code", 0)
            crash_address = exception.get("exception_address", 0)
        else:
            # If no exception, try to get from threads
            bugcheck_code = 0
            crash_address = 0

        # Get bugcheck name and description
        bugcheck_name, bugcheck_description = self._get_bugcheck_info(bugcheck_code)

        # Get crash thread ID
        crash_thread_id = 0
        if exception:
            crash_thread_id = exception.get("thread_id", 0)

        return CrashInfo(
            bugcheck_code=bugcheck_code,
            bugcheck_name=bugcheck_name,
            bugcheck_description=bugcheck_description,
            crash_address=crash_address,
            crash_thread_id=crash_thread_id,
            exception_record=exception,
            parameters=self._get_bugcheck_parameters(),
        )

    def _get_bugcheck_info(self, code: int) -> tuple[str, str]:
        """Get bugcheck name and description."""
        from bsod_analyzer.core.bugcheck_kb import BugcheckKnowledgeBase

        kb = BugcheckKnowledgeBase()
        return kb.get_bugcheck_info(code)

    def _get_bugcheck_parameters(self) -> List[int]:
        """Get bugcheck parameters from exception record."""
        exception = self.get_exception_record()
        if exception and "exception_parameters" in exception:
            return exception["exception_parameters"]
        return []

    def get_loaded_drivers(self) -> List[DriverInfo]:
        """Get list of loaded drivers/modules."""
        drivers = []

        try:
            for module in self._minidump.modules.modules:
                driver_name = module.name.name.decode("utf-8", errors="ignore")

                # Parse timestamp
                timestamp = datetime.fromtimestamp(module.time_date_stamp)

                drivers.append(
                    DriverInfo(
                        name=driver_name,
                        base_address=module.base_address,
                        size=module.size,
                        timestamp=timestamp,
                    )
                )

            logger.debug(f"Found {len(drivers)} loaded drivers")
        except AttributeError:
            logger.warning("No module information found in minidump")
        except Exception as e:
            logger.error(f"Error parsing drivers: {e}")

        return drivers

    def get_stack_traces(self) -> List[StackTrace]:
        """Get stack traces for crashed threads."""
        traces = []

        try:
            # Get thread list
            threads = self._minidump.threads

            for thread in threads.threads:
                frames = []

                try:
                    # Get stack frames
                    stack_frames = thread.stack.walk()

                    for frame in stack_frames:
                        # Find module for this address
                        module_name = self._find_module_for_address(frame.instruction_address)

                        frames.append(
                            StackFrame(
                                instruction_address=frame.instruction_address,
                                module_name=module_name,
                                offset=0,
                            )
                        )

                        # Limit frames
                        if len(frames) >= 50:
                            break

                except Exception as e:
                    logger.debug(f"Error reading stack for thread: {e}")
                    continue

                if frames:
                    traces.append(StackTrace(thread_id=thread.thread_id, frames=frames))

            logger.debug(f"Found {len(traces)} stack traces")

        except AttributeError:
            logger.warning("No thread information found in minidump")
        except Exception as e:
            logger.error(f"Error parsing stack traces: {e}")

        return traces

    def _find_module_for_address(self, address: int) -> str:
        """Find module name for given address."""
        try:
            for module in self._minidump.modules.modules:
                if module.base_address <= address < module.base_address + module.size:
                    return module.name.name.decode("utf-8", errors="ignore")
        except Exception:
            pass
        return "Unknown"

    def get_exception_record(self) -> Optional[dict]:
        """Get exception record if available."""
        try:
            if hasattr(self._minidump, "exception") and self._minidump.exception:
                exc = self._minidump.exception.exception

                return {
                    "exception_code": exc.exception_code,
                    "exception_flags": exc.exception_flags,
                    "exception_address": exc.exception_address,
                    "thread_id": exc.thread_id,
                    "exception_parameters": getattr(exc, "exception_parameters", []),
                }
        except (AttributeError, Exception) as e:
            logger.debug(f"No exception record found: {e}")

        return None

    def get_memory_regions(self) -> List[dict]:
        """Get memory region information."""
        regions = []

        try:
            for region in self._minidump.memory.memory_ranges:
                regions.append(
                    {
                        "base_address": region.start_virtual_address,
                        "size": region.size,
                        "is_readable": True,
                    }
                )
        except AttributeError:
            logger.warning("No memory region information found")

        return regions


def create_parser(file_path: str) -> IMinidumpParser:
    """Factory function to create the appropriate parser based on dump file type.

    This function automatically detects the dump file format and returns
    the appropriate parser:
    - PAGEDU64 signature → PageDumpParser (Windows Complete Memory Dump)
    - MDMP signature → MinidumpParser (standard Minidump)

    Args:
        file_path: Path to the dump file

    Returns:
        Appropriate parser instance (MinidumpParser or PageDumpParser)

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file format is not supported

    Example:
        >>> parser = create_parser("crash.dmp")
        >>> crash_info = parser.extract_crash_info()
        >>> print(f"Bugcheck: 0x{crash_info.bugcheck_code:X}")
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Dump file not found: {path}")

    if path.stat().st_size == 0:
        raise ValueError(f"Empty dump file: {path}")

    # Read signature to determine format
    with open(path, "rb") as f:
        signature = f.read(8)

    # PAGEDU64 format - Complete Memory Dump
    if signature[:8] == b"PAGEDU64":
        logger.info(f"Detected PAGEDU64 format (Complete Memory Dump): {file_path}")
        from bsod_analyzer.core.pagedump_parser import PageDumpParser
        return PageDumpParser(file_path)

    # Standard minidump format
    if signature[:4] == b"MDMP":
        logger.info(f"Detected Minidump format: {file_path}")
        return MinidumpParser(file_path)

    # Unknown format
    raise ValueError(
        f"Unsupported dump file signature: {signature[:8].hex()}. "
        f"Expected 'MDMP' (Minidump) or 'PAGEDU64' (Complete Memory Dump)."
    )
