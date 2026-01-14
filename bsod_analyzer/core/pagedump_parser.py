"""
PAGEDU64 format parser - Windows Complete Memory Dump.

This module provides basic parsing capability for Windows Complete Memory Dump files
(PAGEDU64 format) to extract crash information when kdmp-parser cannot handle them.

Based on Microsoft Debug Help documentation and DUMP_HEADER structure.
"""

import struct
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass
from loguru import logger

from bsod_analyzer.database.models import (
    MinidumpInfo,
    CrashInfo,
    DriverInfo,
    StackTrace,
    StackFrame,
)


@dataclass
class DumpHeader:
    """PAGEDU64 dump file header structure based on DUMP_HEADER64."""

    signature: bytes
    valid_dump: int
    major_version: int
    minor_version: int
    directory_table_base: int
    pfn_database: int = 0
    ps_loaded_module_list: int = 0
    ps_active_process_head: int = 0
    machine_image_type: int = 0
    number_processors: int = 0
    bugcheck_code: int = 0
    bugcheck_parameter1: int = 0
    bugcheck_parameter2: int = 0
    bugcheck_parameter3: int = 0
    bugcheck_parameter4: int = 0
    scratch_redo_log: int = 0
    bugcheck_page_offset: int = 0


@dataclass
class ExceptionRecord64:
    """Exception record structure (EXCEPTION_RECORD64)."""

    exception_code: int
    exception_flags: int
    exception_record: int
    exception_address: int
    number_parameters: int
    parameters: List[int]


class PageDumpParser:
    """Parser for Windows Complete Memory Dump (PAGEDU64) files."""

    # DUMP_HEADER64 structure offsets (verified by hex dump analysis)
    OFFSET_SIGNATURE = 0x0000
    OFFSET_MAJOR_VERSION = 0x0008
    OFFSET_MINOR_VERSION = 0x000C
    OFFSET_DIRECTORY_TABLE_BASE = 0x0010
    OFFSET_MACHINE_IMAGE_TYPE = 0x0030
    OFFSET_NUMBER_PROCESSORS = 0x0034
    OFFSET_BUGCHECK_CODE = 0x0040
    OFFSET_BUGCHECK_PARAM1 = 0x0044
    OFFSET_BUGCHECK_PARAM2 = 0x004C
    OFFSET_BUGCHECK_PARAM3 = 0x0054
    OFFSET_BUGCHECK_PARAM4 = 0x005C
    OFFSET_CONTEXT_RECORD = 0x0200

    # Machine image type constants
    IMAGE_FILE_MACHINE_I386 = 0x014C
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_IA64 = 0x0200
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64

    def __init__(self, file_path: str):
        """Initialize the PAGEDU64 parser.

        Args:
            file_path: Path to the dump file
        """
        self.file_path = Path(file_path)
        self._header: Optional[DumpHeader] = None
        self._context_data: Optional[bytes] = None
        self._validate_file()
        self._parse_header()

    def _validate_file(self):
        """Validate file exists and has correct signature."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"Dump file not found: {self.file_path}")

        if self.file_path.stat().st_size == 0:
            raise ValueError(f"Empty dump file: {self.file_path}")

        # Check signature
        signature = self._read_bytes(0, 8)
        if signature != b"PAGEDU64":
            raise ValueError(
                f"Invalid PAGEDU64 signature: {signature}. "
                f"Expected b'PAGEDU64'"
            )

        logger.info(f"Valid PAGEDU64 file: {self.file_path}, size: {self.file_path.stat().st_size:,} bytes")

    def _read_u32(self, offset: int) -> int:
        """Read 32-bit unsigned integer at offset."""
        data = self._read_bytes(offset, 4)
        return struct.unpack("<I", data)[0]

    def _read_u64(self, offset: int) -> int:
        """Read 64-bit unsigned integer at offset."""
        data = self._read_bytes(offset, 8)
        return struct.unpack("<Q", data)[0]

    def _read_bytes(self, offset: int, size: int) -> bytes:
        """Read raw bytes at offset."""
        with open(self.file_path, "rb") as f:
            f.seek(offset)
            return f.read(size)

    def _parse_header(self):
        """Parse the dump file header."""
        self._header = DumpHeader(
            signature=self._read_bytes(self.OFFSET_SIGNATURE, 8),
            valid_dump=0,
            major_version=self._read_u32(self.OFFSET_MAJOR_VERSION),
            minor_version=self._read_u32(self.OFFSET_MINOR_VERSION),
            directory_table_base=self._read_u64(self.OFFSET_DIRECTORY_TABLE_BASE),
            machine_image_type=self._read_u32(self.OFFSET_MACHINE_IMAGE_TYPE),
            number_processors=self._read_u32(self.OFFSET_NUMBER_PROCESSORS),
            bugcheck_code=self._read_u32(self.OFFSET_BUGCHECK_CODE),
            bugcheck_parameter1=self._read_u64(self.OFFSET_BUGCHECK_PARAM1),
            bugcheck_parameter2=self._read_u64(self.OFFSET_BUGCHECK_PARAM2),
            bugcheck_parameter3=self._read_u64(self.OFFSET_BUGCHECK_PARAM3),
            bugcheck_parameter4=self._read_u64(self.OFFSET_BUGCHECK_PARAM4),
            scratch_redo_log=0,
            bugcheck_page_offset=0,
        )

        logger.info(
            f"Parsed PAGEDU64 header: "
            f"Bugcheck 0x{self._header.bugcheck_code:X}, "
            f"Machine: 0x{self._header.machine_image_type:X}, "
            f"Processors: {self._header.number_processors}"
        )

        logger.debug(
            f"Bugcheck params: "
            f"[0x{self._header.bugcheck_parameter1:X}, "
            f"0x{self._header.bugcheck_parameter2:X}, "
            f"0x{self._header.bugcheck_parameter3:X}, "
            f"0x{self._header.bugcheck_parameter4:X}]"
        )

    def get_dump_header(self) -> DumpHeader:
        """Get the parsed dump header."""
        if self._header is None:
            self._parse_header()
        return self._header

    def parse(self, file_path: str) -> MinidumpInfo:
        """Parse and return dump basic information."""
        header = self.get_dump_header()

        # Get timestamp from file modification time
        timestamp = datetime.fromtimestamp(self.file_path.stat().st_mtime)

        # Map machine image type to architecture
        arch_map = {
            self.IMAGE_FILE_MACHINE_AMD64: "AMD64",
            self.IMAGE_FILE_MACHINE_I386: "I386",
            self.IMAGE_FILE_MACHINE_IA64: "IA64",
            self.IMAGE_FILE_MACHINE_ARM64: "ARM64",
        }
        arch = arch_map.get(
            header.machine_image_type,
            f"UNKNOWN(0x{header.machine_image_type:X})"
        )

        return MinidumpInfo(
            file_path=str(self.file_path),
            file_size=self.file_path.stat().st_size,
            timestamp=timestamp,
            computer_name="",  # Not directly accessible in PAGEDU64 header
            os_version=f"{header.major_version}.{header.minor_version}",
            cpu_architecture=arch,
            number_of_processors=header.number_processors,
            physical_memory=0,  # Would require more complex parsing
        )

    def extract_crash_info(self) -> CrashInfo:
        """Extract crash information from PAGEDU64 dump."""
        header = self.get_dump_header()

        # Get bugcheck name and description
        bugcheck_name, bugcheck_description = self._get_bugcheck_info(header.bugcheck_code)

        # Try to get exception address from parameters
        # For many bugcheck codes, parameter 1 contains the faulting address
        crash_address = header.bugcheck_parameter1

        return CrashInfo(
            bugcheck_code=header.bugcheck_code,
            bugcheck_name=bugcheck_name,
            bugcheck_description=bugcheck_description,
            crash_address=crash_address,
            crash_thread_id=0,  # Not in header
            parameters=[
                header.bugcheck_parameter1,
                header.bugcheck_parameter2,
                header.bugcheck_parameter3,
                header.bugcheck_parameter4,
            ],
            exception_record={
                "exception_code": header.bugcheck_code,
                "exception_address": crash_address,
                "exception_parameters": [
                    header.bugcheck_parameter1,
                    header.bugcheck_parameter2,
                    header.bugcheck_parameter3,
                    header.bugcheck_parameter4,
                ],
            },
        )

    def _get_bugcheck_info(self, code: int) -> tuple[str, str]:
        """Get bugcheck name and description."""
        from bsod_analyzer.core.bugcheck_kb import BugcheckKnowledgeBase

        kb = BugcheckKnowledgeBase()
        return kb.get_bugcheck_info(code)

    def get_loaded_drivers(self) -> List[DriverInfo]:
        """Get list of loaded drivers from PAGEDU64 dump.

        Note: This requires walking the PS_LOADED_MODULE_LIST in kernel memory.
        The PS_LOADED_MODULE_LIST address is in the header, but parsing the
        linked list from the raw dump is complex and requires understanding
        the kernel's memory layout.

        TODO: Implement kernel memory walking to extract driver list.
        """
        logger.warning("Driver extraction from PAGEDU64 not implemented")
        logger.info(
            f"PS_LOADED_MODULE_LIST is at 0x{self._header.ps_loaded_module_list:X}, "
            "but parsing requires memory walking"
        )
        return []

    def get_stack_traces(self) -> List[StackTrace]:
        """Get stack traces from PAGEDU64 dump.

        Note: Stack walking requires the CONTEXT record and symbol information.
        This is complex and typically requires debugging symbols.

        TODO: Implement stack walking from context record.
        """
        logger.warning("Stack trace extraction from PAGEDU64 not implemented")
        return []

    def get_context_registers(self) -> Dict[str, int]:
        """Get CPU register values from context record.

        The CONTEXT record location varies. In some dump formats it's embedded,
        in others it must be found by walking kernel structures.

        Returns:
            Dictionary with register names and values, or empty dict if not available
        """
        # Try to read context at standard offset
        ctx_offset = self.OFFSET_CONTEXT_RECORD
        registers = {}

        try:
            # Read potential context data
            ctx_data = self._read_bytes(ctx_offset, 16)

            # Check if it's valid (not just PAGE filler)
            if ctx_data == b"PAGEPAGEPAGEPA":
                logger.debug(f"No valid CONTEXT record at offset 0x{ctx_offset:X}")
                return {}

            # Try to parse as x64 CONTEXT structure
            # CONTEXT for x64 has specific layout
            registers = self._parse_context_x64(ctx_offset)

        except Exception as e:
            logger.debug(f"Failed to read context registers: {e}")

        return registers

    def _parse_context_x64(self, offset: int) -> Dict[str, int]:
        """Parse x64 CONTEXT structure at offset."""
        registers = {}

        try:
            # CONTEXT.x64 member offsets (simplified)
            # The actual layout depends on CONTEXT_FLAGS
            # Full context would include segment registers, floats, etc.

            # Read P1Home through P6Home and standard registers
            # These are typically at fixed offsets in CONTEXT
            ctx_size = 0x4F0  # Size of x64 CONTEXT structure

            # Check if we have enough data
            if self.file_path.stat().st_size < offset + ctx_size:
                logger.debug("Not enough data for full CONTEXT structure")
                return {}

            # Parse register context (simplified)
            # Offsets are based on CONTEXT having CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
            reg_offsets = {
                "Rax": 0x78,   # P1Home
                "Rcx": 0x80,   # P2Home
                "Rdx": 0x88,   # P3Home
                "Rbx": 0x90,
                "Rsp": 0x98,
                "Rbp": 0xA0,
                "Rsi": 0xA8,
                "Rdi": 0xB0,
                "Rip": 0xB8,   # This is the most important!
                "R8": 0xC0,    # P4Home
                "R9": 0xC8,    # P5Home
                "R10": 0xD0,   # P6Home
                "R11": 0xD8,
                "R12": 0xE0,
                "R13": 0xE8,
                "R14": 0xF0,
                "R15": 0xF8,
            }

            for reg_name, reg_offset in reg_offsets.items():
                val = self._read_u64(offset + reg_offset)
                registers[reg_name] = val

            logger.debug(f"Extracted registers: RIP=0x{registers.get('Rip', 0):X}")

        except Exception as e:
            logger.debug(f"Failed to parse x64 context: {e}")

        return registers

    def get_raw_bytes(self, offset: int, size: int) -> bytes:
        """Read raw bytes from dump file at offset.

        Useful for manual inspection or debugging.

        Args:
            offset: Byte offset in file
            size: Number of bytes to read

        Returns:
            Raw bytes
        """
        return self._read_bytes(offset, size)

    def hex_dump(self, offset: int, size: int = 256) -> str:
        """Create a hex dump of file region.

        Args:
            offset: Starting offset
            size: Number of bytes to dump

        Returns:
            Hex dump string
        """
        data = self._read_bytes(offset, size)
        lines = []

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset + i:08X}: {hex_part:<48} {ascii_part}")

        return "\n".join(lines)


def test_parse_file(file_path: str):
    """Test function to parse and display crash info."""
    print(f"\n{'='*60}")
    print(f"PAGEDU64 Dump File Analysis: {file_path}")
    print(f"{'='*60}\n")

    try:
        parser = PageDumpParser(file_path)

        # Get header
        header = parser.get_dump_header()
        print("Header Information:")
        print(f"  Signature: {header.signature}")
        print(f"  Valid Dump: {header.valid_dump}")
        print(f"  Version: {header.major_version}.{header.minor_version}")
        print(f"  Machine Type: 0x{header.machine_image_type:X}")
        print(f"  Processors: {header.number_processors}")
        print(f"  Directory Table Base: 0x{header.directory_table_base:X}")

        # Get crash info
        crash_info = parser.extract_crash_info()
        print(f"\nCrash Information:")
        print(f"  Bugcheck Code: 0x{crash_info.bugcheck_code:X} ({crash_info.bugcheck_name})")
        print(f"  Description: {crash_info.bugcheck_description}")
        print(f"  Parameters:")
        for i, param in enumerate(crash_info.parameters, 1):
            print(f"    Param {i}: 0x{param:X}")

        # Try to get registers
        registers = parser.get_context_registers()
        if registers:
            print(f"\nCPU Context at Crash:")
            for reg, val in registers.items():
                print(f"  {reg}: 0x{val:016X}")
        else:
            print(f"\nCPU Context: Not available or corrupted")

        # Get basic info
        minidump_info = parser.parse(file_path)
        print(f"\nFile Information:")
        print(f"  File Size: {minidump_info.file_size:,} bytes ({minidump_info.file_size // (1024**2):,} MB)")
        print(f"  Architecture: {minidump_info.cpu_architecture}")
        print(f"  OS Version: {minidump_info.os_version}")
        print(f"  Timestamp: {minidump_info.timestamp}")

        # Show hex dump of header region
        print(f"\nHeader Hex Dump (first 256 bytes):")
        print(parser.hex_dump(0, 256))

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        test_parse_file(sys.argv[1])
    else:
        # Test with the crash.dmp in the project
        test_parse_file(r"S:\vibe_coding\blue-screen-what-happen\crash.dmp")
